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

import okhttp3.ConnectionSpec
import okhttp3.TlsVersion

import android.os.Build
import android.util.Log
import okhttp3.OkHttpClient
import org.conscrypt.Conscrypt
import java.io.IOException
import java.net.InetAddress
import java.net.Socket
import java.security.KeyStore
import java.security.SecureRandom
import java.security.Security
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * 强制启用 TLS 1.3 的套接字工厂包装器
 */
class Tls13EnforcingSocketFactory(private val delegate: SSLSocketFactory) : SSLSocketFactory() {
    init {
        Log.e("XHttp", "Tls13EnforcingSocketFactory created with delegate: ${delegate.javaClass.name}")
    }

    override fun getDefaultCipherSuites(): Array<String> = delegate.defaultCipherSuites
    override fun getSupportedCipherSuites(): Array<String> = delegate.supportedCipherSuites

    override fun createSocket(s: Socket?, host: String?, port: Int, autoClose: Boolean): Socket {
        Log.e("XHttp", "Tls13Enforcing.createSocket(1) $host:$port autoClose=$autoClose")
        return delegate.createSocket(s, host, port, autoClose).enforceTls13()
    }

    override fun createSocket(host: String?, port: Int): Socket {
        Log.e("XHttp", "Tls13Enforcing.createSocket(2) $host:$port")
        return delegate.createSocket(host, port).enforceTls13()
    }

    override fun createSocket(host: String?, port: Int, localHost: InetAddress?, localPort: Int): Socket {
        Log.e("XHttp", "Tls13Enforcing.createSocket(3) $host:$port local=$localHost:$localPort")
        return delegate.createSocket(host, port, localHost, localPort).enforceTls13()
    }

    override fun createSocket(host: InetAddress?, port: Int): Socket {
        Log.e("XHttp", "Tls13Enforcing.createSocket(4) $host:$port")
        return delegate.createSocket(host, port).enforceTls13()
    }

    override fun createSocket(host: InetAddress?, port: Int, localHost: InetAddress?, localPort: Int): Socket {
        Log.e("XHttp", "Tls13Enforcing.createSocket(5) $host:$port local=$localHost:$localPort")
        return delegate.createSocket(host, port, localHost, localPort).enforceTls13()
    }

    private fun Socket.enforceTls13(): Socket {
        if (this is SSLSocket) {
            Log.e("XHttp", "enforceTls13: Got SSLSocket, class=${this.javaClass.name}")
            try {
                val params = sslParameters
                val conscryptClass = Class.forName("org.conscrypt.Conscrypt")
                val setMaxMethod = conscryptClass.getMethod(
                    "setMaxTlsVersion",
                    SSLParameters::class.java,
                    String::class.java
                )
                setMaxMethod.invoke(null, params, "TLSv1.3")
                sslParameters = params
                Log.e("XHttp", "MaxTlsVersion set to TLSv1.3 via reflection")
            } catch (e: Exception) {
                Log.e("XHttp", "Failed to set MaxTlsVersion", e)
            }

            val current = enabledProtocols ?: emptyArray()
            if (!current.contains("TLSv1.3")) {
                enabledProtocols = current + "TLSv1.3"
                Log.e("XHttp", "Enabled protocols: ${enabledProtocols.joinToString()}")
            } else {
                Log.e("XHttp", "TLSv1.3 already in enabled protocols")
            }
        } else {
            Log.e("XHttp", "enforceTls13: Socket is NOT an SSLSocket, class=${this.javaClass.name}")
        }
        return this
    }
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

            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
                Log.e("XHttp", "API level: ${Build.VERSION.SDK_INT}, installing Conscrypt")
                installConscrypt()
            } else {
                Log.e("XHttp", "API level: ${Build.VERSION.SDK_INT}, skip Conscrypt")
            }
        
            // 强制创建 OkHttpClient，并尝试获取其 SSLSocketFactory 类型
            try {
                val client = XHttp.getOkHttpClient()
                val field = OkHttpClient::class.java.getDeclaredField("sslSocketFactory")
                field.isAccessible = true
                val factory = field.get(client)
                Log.e("XHttp", "OkHttp client SSLFactory: ${factory?.javaClass?.name}")
            } catch (e: Exception) {
                Log.e("XHttp", "Failed to read OkHttp sslSocketFactory", e)
            }
        }

        private fun installConscrypt() {
            Log.e("XHttp", "installConscrypt() start")
            try {
                val provider = Conscrypt.newProvider()
                val pos = Security.insertProviderAt(provider, 1)
                Log.e("XHttp", "Provider inserted at $pos: ${provider.name}")
        
                val sslContext = SSLContext.getInstance("TLS", provider)
                val tm = getDefaultTrustManager()
                sslContext.init(null, arrayOf<X509TrustManager>(tm), SecureRandom())
        
                val wrappedFactory = Tls13EnforcingSocketFactory(sslContext.socketFactory)
                Log.e("XHttp", "Wrapped factory class: ${wrappedFactory.javaClass.name}, delegate: ${sslContext.socketFactory.javaClass.name}")
        
                XHttp.getOkHttpClientBuilder().sslSocketFactory(wrappedFactory, tm)
        
                Log.e("XHttp", "TLS 1.3 enforcing factory installed")
            } catch (e: Exception) {
                Log.e("XHttp", "Conscrypt setup failed", e)
            }
        }

        private fun forceTls13OnOkHttp() {
            val spec = ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
                .tlsVersions(TlsVersion.TLS_1_3, TlsVersion.TLS_1_2)  // 优先 TLS 1.3，兼容 1.2
                .allEnabledCipherSuites()  // 允许所有密码套件，避免套件不匹配
                .build()
            
            XHttp.getOkHttpClientBuilder().connectionSpecs(listOf(spec))
        }
        
        private fun getDefaultTrustManager(): X509TrustManager {
            val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            tmf.init(null as KeyStore?)
            @Suppress("UNCHECKED_CAST")
            return tmf.trustManagers.first { it is X509TrustManager } as X509TrustManager
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
