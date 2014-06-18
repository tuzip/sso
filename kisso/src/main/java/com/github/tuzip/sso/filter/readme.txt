
-----------------------------------------------
web.xml配置
-----------------------------------------------
<!-- WafFilter use . -->
<filter>
	<filter-name>WafFilter</filter-name>
	<filter-class>com.github.abci.kisso.filter.WafFilter</filter-class>
	<init-param>
		<param-name>over.url</param-name>
		<param-value>/test/a.html;/test/b.html</param-value>
	</init-param>
	<init-param>
		<param-name>config_tag</param-name>
		<param-value>sso</param-value>
	</init-param>
	<init-param>
      <param-name>filter_xss</param-name>
      <param-value>true</param-value>
    </init-param>
	<init-param>
      <param-name>filter_sql_injection</param-name>
      <param-value>true</param-value>
    </init-param>
</filter>
<filter-mapping>
	<filter-name>WafFilter</filter-name>
	<url-pattern>/*</url-pattern>
</filter-mapping>
-----------------------------------------------


log4j.properties配置
-----------------------------------------------
log4j.appender.waf = org.apache.log4j.RollingFileAppender
log4j.appender.waf.MaxFileSize=1MB
log4j.appender.waf.MaxBackupIndex=7
log4j.appender.waf.file = ${sso.root}/logs/waf.log
log4j.appender.waf.layout = org.apache.log4j.PatternLayout
log4j.appender.waf.layout.conversionPattern = %d [%t] %-5p %c - %m%n
log4j.appender.waf.append = false

-----------------------------------------------

