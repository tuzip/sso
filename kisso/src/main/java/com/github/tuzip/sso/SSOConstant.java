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

/**
 * SSO 常量定义
 * <p>
 * @author   hubin
 * @Date	 2014-5-9
 */
public class SSOConstant {
	/**
	 * 基本常量定义
	 */
	public final static String ENCODING = "UTF-8";
	public final static String ALLCHAR = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	public final static String SSO_SECRET_KEY = "h2wmABdfM7i3K80mAS";
	public final static String CUT_SYMBOL = "#";

	/**
	 * Cookie 设置常量
	 */
	public final static boolean SSO_COOKIE_SECURE = false;
	public final static boolean SSO_COOKIE_HTTPONLY = true;
	public final static int SSO_COOKIE_MAXAGE = -1;
	public final static String SSO_COOKIE_NAME = "uid";
	public final static String SSO_COOKIE_DOMAIN = ".github.com";
	public final static String SSO_COOKIE_PATH = "/";

	/**
	 * SSO 登录 Cookie 校验常量
	 */
	public final static boolean SSO_COOKIE_BROWSER = true;
	public final static boolean SSO_COOKIE_CHECKIP = false;
	public final static boolean SSO_COOKIE_CACHE = false;

	/**
	 * 登录相关常量
	 */
	public final static String SSO_LOGIN_URL = "sso.github.com";
}
