/**
 * Copyright (c) 2011-2014, hubin (243194995@qq.com).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.github.tuzip.sso;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.tuzip.sso.common.util.PropertiesUtil;

/**
 * SSO 配置文件解析
 * <p>
 * @author   hubin
 * @Date	 2014-5-12 	 
 */
public class SSOConfig {
	private final static Logger logger = LoggerFactory.getLogger(SSOConfig.class);
	private static PropertiesUtil prop = null;

	static {
		/**
		 * SSO 资源文件初始化
		 */
		if (prop == null) {
			InputStream in = SSOConfig.class.getResourceAsStream("/sso.properties");
			Properties p = new Properties();
			try {
				p.load(in);
				prop = new PropertiesUtil(p);
			} catch (IOException e) {
				logger.error("read sso.properties error. ", e.toString());
			}
		}
	}

	/**
	 * 编码格式默认 UTF-8
	 */
	public static String getEncoding() {
		return prop.get("sso.encoding", SSOConstant.ENCODING);
	}

	/**
	 * 密钥
	 */
	public static String getSecretKey() {
		return prop.get("sso.secretkey", SSOConstant.SSO_SECRET_KEY);
	}

	/**
	 * Cookie 只允许https协议传输
	 */
	public static boolean getCookieSecure() {
		return prop.getBoolean("sso.cookie.secure", SSOConstant.SSO_COOKIE_SECURE);
	}

	/**
	 * Cookie 只读,不允许 Js访问
	 */
	public static boolean getCookieHttponly() {
		return prop.getBoolean("sso.cookie.httponly", SSOConstant.SSO_COOKIE_HTTPONLY);
	}

	/**
	 * Cookie 超时时间
	 */
	public static int getCookieMaxage() {
		return prop.getInt("sso.cookie.maxage", SSOConstant.SSO_COOKIE_MAXAGE);
	}

	/**
	 * Cookie 名称
	 */
	public static String getCookieName() {
		return prop.get("sso.cookie.name", SSOConstant.SSO_COOKIE_NAME);
	}

	/**
	 * Cookie 所在域
	 */
	public static String getCookieDomain() {
		return prop.get("sso.cookie.domain", SSOConstant.SSO_COOKIE_DOMAIN);
	}

	/**
	 * Cookie 域路径
	 */
	public static String getCookiePath() {
		return prop.get("sso.cookie.path", SSOConstant.SSO_COOKIE_PATH);
	}

	/**
	 * Cookie 开启浏览器版本校验
	 */
	public static boolean getCookieBrowser() {
		return prop.getBoolean("sso.cookie.browser", SSOConstant.SSO_COOKIE_BROWSER);
	}

	/**
	 * Cookie 开启IP校验
	 */
	public static boolean getCookieCheckip() {
		return prop.getBoolean("sso.cookie.checkip", SSOConstant.SSO_COOKIE_CHECKIP);
	}

	/**
	 * Cookie 开启缓存 Token
	 */
	public static boolean getCookieCache() {
		return prop.getBoolean("sso.cookie.cache", SSOConstant.SSO_COOKIE_CACHE);
	}

	/**
	 * 自定义Token Class
	 */
	public static String getTokenClass() {
		return prop.get("sso.token.class", SSOConstant.SSO_TOKEN_CLASS);
	}
	
	/**
	 * SSO 登录地址
	 */
	public static String getLoginUrl() {
		return prop.get("sso.login.url", SSOConstant.SSO_LOGIN_URL);
	}
}
