package net.corda.nodeapi.internal.protonwrapper.netty

import io.netty.buffer.ByteBuf
import io.netty.channel.ChannelDuplexHandler
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelPromise
import io.netty.channel.socket.SocketChannel
import io.netty.handler.ssl.SslHandler
import io.netty.handler.ssl.SslHandshakeCompletionEvent
import io.netty.util.ReferenceCountUtil
import net.corda.core.identity.CordaX500Name
import net.corda.core.utilities.contextLogger
import net.corda.core.utilities.debug
import net.corda.nodeapi.internal.crypto.x509
import net.corda.nodeapi.internal.protonwrapper.engine.EventProcessor
import net.corda.nodeapi.internal.protonwrapper.messages.ReceivedMessage
import net.corda.nodeapi.internal.protonwrapper.messages.impl.ReceivedMessageImpl
import net.corda.nodeapi.internal.protonwrapper.messages.impl.SendableMessageImpl
import org.apache.qpid.proton.engine.ProtonJTransport
import org.apache.qpid.proton.engine.Transport
import org.apache.qpid.proton.engine.impl.ProtocolTracer
import org.apache.qpid.proton.framing.TransportFrame
import java.net.InetSocketAddress
import java.security.cert.X509Certificate

/**
 *  An instance of AMQPChannelHandler sits inside the netty pipeline and controls the socket level lifecycle.
 *  It also add some extra checks to the SSL handshake to support our non-standard certificate checks of legal identity.
 *  When a valid SSL connection is made then it initialises a proton-j engine instance to handle the protocol layer.
 */
internal class AMQPChannelHandler(private val serverMode: Boolean,
                                  private val allowedRemoteLegalNames: Set<CordaX500Name>?,
                                  private val userName: String?,
                                  private val password: String?,
                                  private val trace: Boolean,
                                  private val onOpen: (Pair<SocketChannel, ConnectionChange>) -> Unit,
                                  private val onClose: (Pair<SocketChannel, ConnectionChange>) -> Unit,
                                  private val onReceive: (ReceivedMessage) -> Unit) : ChannelDuplexHandler() {
    companion object {
        val log = contextLogger()
    }
    private lateinit var remoteAddress: InetSocketAddress
    private var localCert: X509Certificate? = null
    private var remoteCert: X509Certificate? = null
    private var eventProcessor: EventProcessor? = null
    private var badCert: Boolean = false

    override fun channelActive(ctx: ChannelHandlerContext) {
        val ch = ctx.channel()
        remoteAddress = ch.remoteAddress() as InetSocketAddress
        val localAddress = ch.localAddress() as InetSocketAddress
        log.info("New client connection ${ch.id()} from $remoteAddress to $localAddress")
    }

    private fun createAMQPEngine(ctx: ChannelHandlerContext) {
        val ch = ctx.channel()
        eventProcessor = EventProcessor(ch, serverMode, localCert!!.subjectX500Principal.toString(), remoteCert!!.subjectX500Principal.toString(), userName, password)
        val connection = eventProcessor!!.connection
        val transport = connection.transport as ProtonJTransport
        if (trace) {
            transport.protocolTracer = object : ProtocolTracer {
                override fun sentFrame(transportFrame: TransportFrame) {
                    log.info("${transportFrame.body}")
                }

                override fun receivedFrame(transportFrame: TransportFrame) {
                    log.info("${transportFrame.body}")
                }
            }
        }
        ctx.fireChannelActive()
        eventProcessor!!.processEventsAsync()
    }

    override fun channelInactive(ctx: ChannelHandlerContext) {
        val ch = ctx.channel()
        log.info("Closed client connection ${ch.id()} from $remoteAddress to ${ch.localAddress()}")
        onClose(Pair(ch as SocketChannel, ConnectionChange(remoteAddress, remoteCert, false, badCert)))
        eventProcessor?.close()
        ctx.fireChannelInactive()
    }

    override fun userEventTriggered(ctx: ChannelHandlerContext, evt: Any) {
        if (evt !is SslHandshakeCompletionEvent) return

        fun fail(message: String, ex: Throwable? = null) {
            badCert = true
            log.error(message)
            if (ex != null && log.isTraceEnabled)
                log.trace("SSL handshake failure", ex)
            ctx.close()
        }

        if (!evt.isSuccess) {
            fail("SSL handshake failure, other side might be expecting a different protocol: ${evt.cause().message}", evt.cause())
            return
        }
        val sslHandler = ctx.pipeline().get(SslHandler::class.java)
        val session = sslHandler.engine().session
        if (session.peerCertificates.isEmpty()) {
            fail("SSL handshake failure, other side didn't send a client certificate. " +
                    "Might be a web browser or crawler instead of a Corda node?")
            return
        }
        localCert = session.localCertificates[0].x509   // We should always have a local certificate because we set it.
        remoteCert = session.peerCertificates[0].x509
        val x500Principal = remoteCert!!.subjectX500Principal
        val remoteX500Name = try {
            CordaX500Name.build(x500Principal)
        } catch (ex: IllegalArgumentException) {
            fail("Certificate subject not a valid Corda X500 name ('$x500Principal'): " +
                    "might be an old Corda node or one joined to a different compatibility zone")
            return
        }
        if (allowedRemoteLegalNames != null && remoteX500Name !in allowedRemoteLegalNames) {
            fail("Provided certificate subject $remoteX500Name not allowed, not in the zone's network map.")
            return
        }
        log.info("Handshake completed with peer name $remoteX500Name")
        createAMQPEngine(ctx)
        onOpen(Pair(ctx.channel() as SocketChannel, ConnectionChange(remoteAddress, remoteCert, true, false)))
    }

    @Suppress("OverridingDeprecatedMember")
    override fun exceptionCaught(ctx: ChannelHandlerContext, cause: Throwable) {
        log.warn("Closing channel due to nonrecoverable exception ${cause.message}")
        if (log.isTraceEnabled) {
            log.trace("Pipeline uncaught exception", cause)
        }
        ctx.close()
    }

    override fun channelRead(ctx: ChannelHandlerContext, msg: Any) {
        try {
            if (msg is ByteBuf) {
                eventProcessor!!.transportProcessInput(msg)
            }
        } finally {
            ReferenceCountUtil.release(msg)
        }
        eventProcessor!!.processEventsAsync()
    }

    override fun write(ctx: ChannelHandlerContext, msg: Any, promise: ChannelPromise) {
        try {
            try {
                when (msg) {
                // Transfers application packet into the AMQP engine.
                    is SendableMessageImpl -> {
                        val inetAddress = InetSocketAddress(msg.destinationLink.host, msg.destinationLink.port)
                        require(inetAddress == remoteAddress) {
                            "Message for incorrect endpoint $inetAddress expected $remoteAddress"
                        }
                        require(CordaX500Name.parse(msg.destinationLegalName) == CordaX500Name.build(remoteCert!!.subjectX500Principal)) {
                            "Message for incorrect legal identity ${msg.destinationLegalName} expected ${remoteCert!!.subjectX500Principal}"
                        }
                        log.debug { "channel write ${msg.applicationProperties["_AMQ_DUPL_ID"]}" }
                        eventProcessor!!.transportWriteMessage(msg)
                    }
                // A received AMQP packet has been completed and this self-posted packet will be signalled out to the
                // external application.
                    is ReceivedMessage -> {
                        onReceive(msg)
                    }
                // A general self-posted event that triggers creation of AMQP frames when required.
                    is Transport -> {
                        eventProcessor!!.transportProcessOutput(ctx)
                    }
                // A self-posted event that forwards status updates for delivered packets to the application.
                    is ReceivedMessageImpl.MessageCompleter -> {
                        eventProcessor!!.complete(msg)
                    }
                }
            } catch (ex: Exception) {
                log.error("Error in AMQP write processing", ex)
                throw ex
            }
        } finally {
            ReferenceCountUtil.release(msg)
        }
        eventProcessor!!.processEventsAsync()
    }
}