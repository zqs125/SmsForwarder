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
import org.conscrypt.Conscrypt
import java.security.KeyStore
import java.security.SecureRandom
import java.security.Security
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

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
            }
        }

        private fun installConscrypt() {
            try {
                // 1. 通过系统属性告知 Conscrypt 允许 TLS 1.3
                System.setProperty("org.conscrypt.maxTlsVersion", "TLSv1.3")
        
                // 2. 注册 Conscrypt 为最高优先级安全提供者
                val provider = Conscrypt.newProvider()
                Security.insertProviderAt(provider, 1)
        
                // 3. 创建 Conscrypt 的 SSLContext 并设为默认
                val sslContext = SSLContext.getInstance("TLS", provider)
                sslContext.init(null, arrayOf(getDefaultTrustManager()), SecureRandom())
                SSLContext.setDefault(sslContext)
        
                Log.e("XHttp", "Conscrypt default SSLContext installed, maxTlsVersion=TLSv1.3")
            } catch (e: Exception) {
                Log.e("XHttp", "Conscrypt install failed", e)
            }
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
