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
package com.github.tuzip.sso.client;

import java.io.IOException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.tuzip.sso.Encrypt;
import com.github.tuzip.sso.SSOConfig;
import com.github.tuzip.sso.SSOConstant;
import com.github.tuzip.sso.SSOToken;
import com.github.tuzip.sso.TokenCache;
import com.github.tuzip.sso.TokenCacheMap;
import com.github.tuzip.sso.common.Browser;
import com.github.tuzip.sso.common.CookieHelper;
import com.github.tuzip.sso.common.IpHelper;
import com.github.tuzip.sso.common.encrypt.AES;
import com.github.tuzip.sso.common.util.HttpUtil;

/**
 * SSO客户端帮助类
 * <p>
 * @author   hubin
 * @Date	 2014-5-8 	 
 */
public class SSOHelper {
	private final static Logger logger = LoggerFactory.getLogger(SSOHelper.class);

	/**
	 * 获取当前请求 JsonToken
	 * <p>
	 * @param request
	 * @param encrypt
	 * 				对称加密算法类
	 * @return String 当前Token的json格式值
	 */
	public static String getJsonToken(HttpServletRequest request, Encrypt encrypt) {
		Cookie uid = CookieHelper.findCookieByName(request, SSOConfig.getCookieName());
		if (uid != null) {
			String jsonToken = uid.getValue();
			String[] tokenAttr = new String[2];
			try {
				jsonToken = encrypt.decrypt(jsonToken, SSOConfig.getSecretKey());
				tokenAttr = jsonToken.split(SSOConstant.CUT_SYMBOL);
			} catch (Exception e) {
				logger.info("jsonToken decrypt error.");
				e.printStackTrace();
			}
			/**
			 * 判断是否认证浏览器
			 * 混淆信息
			 */
			if (SSOConfig.getCookieBrowser()) {
				if (Browser.isLegalUserAgent(request, tokenAttr[0], tokenAttr[1])) {
					return tokenAttr[0];
				} else {
					/**
					 * 签名验证码失败
					 */
					logger.error("SSOHelper getSSOToken, find Browser is illegal.");
				}
			} else {
				/**
				 * 不需要认证浏览器信息混淆
				 * 返回JsonToken
				 */
				return tokenAttr[0];
			}
		}

		return null;
	}

	/**
	 * 获取当前请求 JsonToken
	 * <p>
	 * @param request
	 * @return String 当前Token的json格式值
	 */
	public static String getJsonToken(HttpServletRequest request) {
		return getJsonToken(request, new AES());
	}

	/**
	 * 获取当前请求 SSOToken
	 * <p>
	 * @param request
	 * @return SSOToken
	 */
	public static SSOToken getSSOToken(HttpServletRequest request) {
		return getSSOToken(request, new AES(), new TokenCacheMap());
	}

	/**
	 * 获取当前请求 SSOToken
	 * <p>
	 * @param request
	 * @param encrypt
	 * 				对称加密算法类
	 * @return SSOToken
	 */
	public static SSOToken getSSOToken(HttpServletRequest request, Encrypt encrypt) {
		return getSSOToken(request, encrypt, new TokenCacheMap());
	}

	/**
	 * 获取当前请求 SSOToken
	 * <p>
	 * @param request
	 * @param encrypt
	 * 				对称加密算法类
	 * @return SSOToken
	 */
	public static SSOToken getSSOToken(HttpServletRequest request, Encrypt encrypt, TokenCache cache) {
		SSOToken token = cacheSSOToken(request, encrypt, cache);
		return checkIp(request, token);
	}

	/**
	 * SSOToken 是否缓存至 session处理逻辑
	 * <p>
	 * @param request
	 * @param encrypt
	 * 				对称加密算法类
	 * @return SSOToken
	 */
	private static SSOToken cacheSSOToken(HttpServletRequest request, Encrypt encrypt, TokenCache cache) {
		SSOToken token = null;
		/**
		 * 判断 SSOToken 是否缓存至 Map
		 * 减少Cookie解密耗时
		 */
		if (SSOConfig.getCookieCache() && cache != null) {
			token = (SSOToken) cache.get(hashCookie(request));
		}

		/**
		 * SSOToken 为 null
		 * 执行以下逻辑
		 */
		if (token == null) {
			String jsonToken = getJsonToken(request, encrypt);
			if (jsonToken == null || "".equals(jsonToken)) {
				/**
				 * 未登录请求
				 */
				logger.info("jsonToken is null.");
				return null;
			} else {
				token = new SSOToken();
				token = (SSOToken) token.parseToken(jsonToken);

				/**
				 * 判断 SSOToken 是否缓存至 session
				 * 减少解密次数、提高访问速度
				 */
				if (SSOConfig.getCookieCache() && cache != null) {
					cache.set(hashCookie(request), token);
				}
			}
		}
		return token;
	}

	/**
	 * 检查 IP 与登录 IP 是否一致
	 * <p>
	 * @param request
	 * @param token
	 * 				登录票据
	 * @return SSOToken
	 */

	private static SSOToken checkIp(HttpServletRequest request, SSOToken token) {
		/**
		 * 判断是否检查 IP 一致性
		 */
		if (SSOConfig.getCookieCheckip()) {
			String ip = IpHelper.getIpAddr(request);
			if (token != null && ip != null && !ip.equals(token.getUserIp())) {
				/**
				 * 检查 IP 与登录IP 不一致返回 null
				 */
				logger.info("ip inconsistent! return token null, token userIp:{}, reqIp:{}",
						new Object[] { token.getUserIp(), ip });
				return null;
			}
		}
		return token;
	}

	/**
	 * 退出当前登录状态
	 * <p>
	 * @param request
	 * @param response
	 * @return boolean <p>true 成功, false 失败</p>
	 */
	public static boolean logout(HttpServletRequest request, HttpServletResponse response) {
		return logout(request, response, new TokenCacheMap());
	}

	/**
	 * 退出当前登录状态
	 * <p>
	 * @param request
	 * @param response
	 * @param TokenCache
	 * @return boolean <p>true 成功, false 失败</p>
	 */
	public static boolean logout(HttpServletRequest request, HttpServletResponse response, TokenCache cache) {
		/**
		 * SSOToken 如果开启了session缓存
		 * 删除缓存记录
		 */
		if (SSOConfig.getCookieCache()) {
			cache.delete(hashCookie(request));
		}
		/**
		 * 删除登录 Cookie
		 */
		return CookieHelper.clearCookieByName(request, response, SSOConfig.getCookieName(),
				SSOConfig.getCookieDomain(), SSOConfig.getCookiePath());
	}

	/**
	 * 重新登录
	 * <p>
	 * 退出当前登录状态、重定向至登录页.
	 * @param request
	 * @param response
	 */
	public static void loginAgain(HttpServletRequest request, HttpServletResponse response) throws IOException {
		//logout
		logout(request, response);
		String retUrl = HttpUtil.getQueryString(request, SSOConfig.getEncoding());
		logger.debug("loginAgain redirect pageUrl.." + retUrl);

		//redirect login page
		response.sendRedirect(HttpUtil.encodeRetURL(SSOConfig.getLoginUrl(), "ReturnURL", retUrl));
	}
	
	/**
	 * Cookie加密值 Hash
	 * <p>
	 * @param request
	 * @return String
	 */
	public static String hashCookie(HttpServletRequest request) {
		Cookie uid = CookieHelper.findCookieByName(request, SSOConfig.getCookieName());
		if (uid != null) {
			/**
			 * MD5 会重复处理不采用
			 * 直接返回Cookie加密内容为key
			 */
			return uid.getValue();
		}
		return null;
	}
}
