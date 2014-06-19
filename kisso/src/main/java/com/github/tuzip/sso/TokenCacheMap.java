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

import java.util.HashMap;

/**
 * Token缓存到HashMap
 * <p>
 * @author   hubin
 * @Date	 2014-6-17 	 
 */
public class TokenCacheMap extends TokenCache {
	/**
	 * Token Map
	 */
	private static HashMap<String, Token> tokenMap = new HashMap<String, Token>();

	/**
	 * 根据key获取SSO票据
	 * <p>
	 * @param key 关键词
	 * @return Token	SSO票据
	 */
	@Override
	public Token get(String key) {
		return tokenMap.get(key);
	}

	/**
	 * 设置SSO票据
	 * <p>
	 * @param key 关键词
	 */
	@Override
	public void set(String key, Token token) {
		tokenMap.put(key, token);
	}

	/**
	 * 删除SSO票据
	 * <p>
	 * @param key 关键词
	 */
	@Override
	public void delete(String key) {
		tokenMap.remove(key);
	}
	
}
