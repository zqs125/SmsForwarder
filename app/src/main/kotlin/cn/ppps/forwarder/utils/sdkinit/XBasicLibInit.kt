package cn.ppps.forwarder.utils.sdkinit

import android.app.Application
import cn.ppps.forwarder.App
import cn.ppps.forwarder.core.BaseActivity
import cn.ppps.forwarder.utils.SettingUtils
import cn.ppps.forwarder.utils.XToastUtils
import com.xuexiang.xaop.XAOP
import com.xuexiang.xhttp2.XHttp
import com.xuexiang.xhttp2.XHttpSDK
import com.xuexiang.xhttp2.cache.model.CacheMode
import com.xuexiang.xpage.PageConfig
import com.xuexiang.xrouter.launcher.XRouter
import com.xuexiang.xui.XUI
import com.xuexiang.xutil.XUtil
import com.xuexiang.xutil.common.StringUtils

import okhttp3.OkHttpClient
import java.security.SecureRandom
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import org.conscrypt.Conscrypt

import okhttp3.ConnectionSpec
import okhttp3.TlsVersion

import java.net.InetAddress
import java.net.Socket
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

import android.util.Log

/**
 * 强制所有连接只使用 TLS 1.3 的 SocketFactory
 */
class Tls13OnlySocketFactory(private val delegate: SSLSocketFactory) : SSLSocketFactory() {

    override fun getDefaultCipherSuites(): Array<String> = delegate.defaultCipherSuites
    override fun getSupportedCipherSuites(): Array<String> = delegate.supportedCipherSuites

    private fun enableTls13(socket: Socket): Socket {
        if (socket is SSLSocket) {
            socket.enabledProtocols = arrayOf("TLSv1.3")
        }
        return socket
    }

    override fun createSocket(): Socket = enableTls13(delegate.createSocket())
    override fun createSocket(host: String, port: Int): Socket = enableTls13(delegate.createSocket(host, port))
    override fun createSocket(host: String, port: Int, localHost: InetAddress, localPort: Int): Socket =
        enableTls13(delegate.createSocket(host, port, localHost, localPort))
    override fun createSocket(host: InetAddress, port: Int): Socket = enableTls13(delegate.createSocket(host, port))
    override fun createSocket(address: InetAddress, port: Int, localAddress: InetAddress, localPort: Int): Socket =
        enableTls13(delegate.createSocket(address, port, localAddress, localPort))
    // 关键：必须实现的 Android 扩展方法
    override fun createSocket(s: Socket, host: String, port: Int, autoClose: Boolean): Socket =
        enableTls13(delegate.createSocket(s, host, port, autoClose))
}


/**
 * X系列基础库初始化
 *
 * @author xuexiang
 * @since 2019-06-30 23:54
 */
class XBasicLibInit private constructor() {
    companion object {
        /**
         * 初始化基础库SDK
         */
        fun init(application: Application) {
            //工具类
            initXUtil(application)

            //网络请求框架
            initXHttp2(application)

            //页面框架
            initXPage(application)

            //切片框架
            initXAOP(application)

            //UI框架
            initXUI(application)

            //路由框架
            initRouter(application)
        }

        /**
         * 初始化XUtil工具类
         */
        private fun initXUtil(application: Application) {
            XUtil.init(application)
            XUtil.debug(App.isDebug)
        }

        /**
         * 初始化XHttp2
         */
        private fun initXHttp2(application: Application) {
            /*
            //初始化网络请求框架，必须首先执行
            XHttpSDK.init(application)
            //需要调试的时候执行
            if (App.isDebug) {
                XHttpSDK.debug()
            }
            //设置网络请求的全局基础地址
            XHttpSDK.setBaseUrl("https://gitee.com/")
            //设置自定义的日志打印拦截器
            //XHttpSDK.debug(LoggingInterceptor())
            //设置动态参数添加拦截器
            //XHttpSDK.addInterceptor(CustomDynamicInterceptor())
            //请求失效校验拦截器
            //XHttpSDK.addInterceptor(CustomExpiredInterceptor())
            //设置全局超时时间
            XHttp.getInstance()
                .debug(App.isDebug)
                .setCacheMode(CacheMode.NO_CACHE)
                .setTimeout(SettingUtils.requestTimeout * 1000L) //单次超时时间
            //.setRetryCount(SettingUtils.requestRetryTimes) //超时重试的次数
            //.setRetryDelay(SettingUtils.requestDelayTime * 1000) //超时重试的延迟时间
            //.setRetryIncreaseDelay(SettingUtils.requestDelayTime * 1000) //超时重试叠加延时
            */

            // 1. 必须首先执行
            XHttpSDK.init(application)
        
            // 2. 构建支持 TLS 1.3 的自定义 OkHttpClient
            val okHttpClient = buildTls13OkHttpClient()
        
            // 3. 注入到 XHttp2 中（注意是 XHttp 的实例方法）
            XHttp.getInstance().setOkclient(okHttpClient)
        
            // 4. 设置全局 BaseUrl
            XHttpSDK.setBaseUrl("https://gitee.com/")
        
            // 5. 调试开关
            if (App.isDebug) {
                XHttpSDK.debug()
            }
            
        }

        private fun buildTls13OkHttpClient(): OkHttpClient {
            val sslContext = SSLContext.getInstance("TLS", Conscrypt.newProvider())
            sslContext.init(null, null, SecureRandom())
        
            val tls13Factory = Tls13OnlySocketFactory(sslContext.socketFactory)
        
            val trustAllManager = object : X509TrustManager {
                override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
                override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
                override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
            }
        
            return OkHttpClient.Builder()
                .sslSocketFactory(tls13Factory, trustAllManager)
                .addInterceptor { chain ->
                    val response = chain.proceed(chain.request())
                    val handshake = response.handshake()          // 方法调用
                    val tlsVersion = handshake?.tlsVersion()?.javaName()
                    val cipher = handshake?.cipherSuite()?.javaName()
                    Log.d("TlsTest", "协议: $tlsVersion, 加密套件: $cipher")
                    response
                }
                .connectTimeout(SettingUtils.requestTimeout * 1000L, TimeUnit.MILLISECONDS)
                .readTimeout(SettingUtils.requestTimeout * 1000L, TimeUnit.MILLISECONDS)
                .writeTimeout(SettingUtils.requestTimeout * 1000L, TimeUnit.MILLISECONDS)
                .build()
        }

        /**
         * 初始化XPage页面框架
         */
        private fun initXPage(application: Application) {
            PageConfig.getInstance()
                .debug(App.isDebug)
                .setContainActivityClazz(BaseActivity::class.java)
                .init(application)
        }

        /**
         * 初始化XAOP
         */
        private fun initXAOP(application: Application) {
            XAOP.init(application)
            XAOP.debug(App.isDebug)
            //设置动态申请权限切片 申请权限被拒绝的事件响应监听
            XAOP.setOnPermissionDeniedListener { permissionsDenied: List<String?>? ->
                XToastUtils.error(
                    "权限申请被拒绝:" + StringUtils.listToString(permissionsDenied, ",")
                )
            }
        }

        /**
         * 初始化XUI框架
         */
        private fun initXUI(application: Application) {
            XUI.init(application)
            XUI.debug(App.isDebug)
        }

        /**
         * 初始化路由框架
         */
        private fun initRouter(application: Application) {
            // 这两行必须写在init之前，否则这些配置在init过程中将无效
            if (App.isDebug) {
                XRouter.openLog() // 打印日志
                XRouter.openDebug() // 开启调试模式(如果在InstantRun模式下运行，必须开启调试模式！线上版本需要关闭,否则有安全风险)
            }
            XRouter.init(application)
        }
    }

    init {
        throw UnsupportedOperationException("u can't instantiate me...")
    }
}
