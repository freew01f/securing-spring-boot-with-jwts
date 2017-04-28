package com.example;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.json.JSONObject;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;


@SpringBootApplication
@RestController
@EnableAutoConfiguration
public class DemoApplication {

    // main函数，Spring Boot程序入口
	public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
	}

	// 根目录映射 Get访问方式 直接返回一个字符串
	@RequestMapping("/")
	Map<String, String> hello() {
        Map<String,String> map=new HashMap<String,String>();
        map.put("content", "hello freewolf~");
        return map;
	}
}

class JSONResult{
    public static String fillResultString(Integer status, String message, Object result){
        JSONObject jsonObject = new JSONObject(){{
            put("status", status);
            put("message", message);
            put("result", result);
        }};

        return jsonObject.toString();
    }
}

@RestController
class UserController {

	// 路由映射到/users
	@RequestMapping(value = "/users", produces="application/json;charset=UTF-8")
	public String usersList() {

        ArrayList<String> users =  new ArrayList<String>(){{
            add("freewolf");
            add("tom");
            add("jerry");
        }};

		return JSONResult.fillResultString(0, "", users);
	}

    @RequestMapping(value = "/hello", produces="application/json;charset=UTF-8")
    public String hello() {
        ArrayList<String> users =  new ArrayList<String>(){{ add("hello"); }};
        return JSONResult.fillResultString(0, "", users);
    }

    @RequestMapping(value = "/world", produces="application/json;charset=UTF-8")
    public String world() {
        ArrayList<String> users =  new ArrayList<String>(){{ add("world"); }};
        return JSONResult.fillResultString(0, "", users);
    }
}


@Configuration
@EnableWebSecurity
class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    // 设置 HTTP 验证规则
	@Override
	protected void configure(HttpSecurity http) throws Exception {
        // 关闭csrf验证
		http.csrf().disable()
                // 对请求进行认证
                .authorizeRequests()
                // 所有 / 的所有请求 都放行
				.antMatchers("/").permitAll()
                // 所有 /login 的POST请求 都放行
				.antMatchers(HttpMethod.POST, "/login").permitAll()
                // 添加权限检测
                .antMatchers("/hello").hasAuthority("AUTH_WRITE")
                // 角色检测
                .antMatchers("/world").hasRole("ADMIN")
                // 所有请求需要身份认证
				.anyRequest().authenticated()
            .and()
				// 添加一个过滤器 所有访问 /login 的请求交给 JWTLoginFilter 来处理 这个类处理所有的JWT相关内容
				.addFilterBefore(new JWTLoginFilter("/login", authenticationManager()),
                        UsernamePasswordAuthenticationFilter.class)
				// 添加一个过滤器验证其他请求的Token是否合法
				.addFilterBefore(new JWTAuthenticationFilter(),
						UsernamePasswordAuthenticationFilter.class);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 使用自定义身份验证组件
        auth.authenticationProvider(new CustomAuthenticationProvider());

    }
}

class TokenAuthenticationService {
	static final long EXPIRATIONTIME = 432_000_000;     // 5天
	static final String SECRET = "P@ssw02d";            // JWT密码
	static final String TOKEN_PREFIX = "Bearer";        // Token前缀
	static final String HEADER_STRING = "Authorization";// 存放Token的Header Key

	static void addAuthentication(HttpServletResponse response, String username) {
        // 生成JWT
		String JWT = Jwts.builder()
                // 保存权限（角色）
                .claim("authorities", "ROLE_ADMIN,AUTH_WRITE")
                // 用户名写入标题
                .setSubject(username)
                // 有效期设置
				.setExpiration(new Date(System.currentTimeMillis() + EXPIRATIONTIME))
                // 签名设置
				.signWith(SignatureAlgorithm.HS512, SECRET)
				.compact();

		// 将 JWT 写入 body
        try {
            response.setContentType("application/json");
            response.setStatus(HttpServletResponse.SC_OK);
            response.getOutputStream().println(JSONResult.fillResultString(0, "", JWT));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

	static Authentication getAuthentication(HttpServletRequest request) {
        // 从Header中拿到token
        String token = request.getHeader(HEADER_STRING);

		if (token != null) {
            // 解析 Token
            Claims claims = Jwts.parser()
                    // 验签
					.setSigningKey(SECRET)
                    // 去掉 Bearer
					.parseClaimsJws(token.replace(TOKEN_PREFIX, ""))
					.getBody();

            // 拿用户名
            String user = claims.getSubject();

            // 得到 权限（角色）
            List<GrantedAuthority> authorities =  AuthorityUtils.commaSeparatedStringToAuthorityList((String) claims.get("authorities"));

            // 返回验证令牌
            return user != null ?
					new UsernamePasswordAuthenticationToken(user, null, authorities) :
					null;
		}
		return null;
	}
}

// 自定义身份认证验证组件
class CustomAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 获取认证的用户名 & 密码
        String name = authentication.getName();
        String password = authentication.getCredentials().toString();

        // 认证逻辑
        if (name.equals("admin") && password.equals("123456")) {

            // 这里设置权限和角色
            ArrayList<GrantedAuthority> authorities = new ArrayList<>();
            authorities.add( new GrantedAuthorityImpl("ROLE_ADMIN") );
            authorities.add( new GrantedAuthorityImpl("AUTH_WRITE") );
            // 生成令牌
            Authentication auth = new UsernamePasswordAuthenticationToken(name, password, authorities);
            return auth;
        }else {
            throw new BadCredentialsException("密码错误~");
        }
    }

    // 是否可以提供输入类型的认证服务
    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }

}

class JWTLoginFilter extends AbstractAuthenticationProcessingFilter {

	public JWTLoginFilter(String url, AuthenticationManager authManager) {
        super(new AntPathRequestMatcher(url));
        setAuthenticationManager(authManager);
	}

	@Override
	public Authentication attemptAuthentication(
			HttpServletRequest req, HttpServletResponse res)
			throws AuthenticationException, IOException, ServletException {

	    // JSON反序列化成 AccountCredentials
		AccountCredentials creds = new ObjectMapper().readValue(req.getInputStream(), AccountCredentials.class);

        // 返回一个验证令牌
        return getAuthenticationManager().authenticate(
				new UsernamePasswordAuthenticationToken(
						creds.getUsername(),
						creds.getPassword()
				)
		);
	}

	@Override
	protected void successfulAuthentication(
			HttpServletRequest req,
			HttpServletResponse res, FilterChain chain,
			Authentication auth) throws IOException, ServletException {
		TokenAuthenticationService.addAuthentication(res, auth.getName());
	}


    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        response.setContentType("application/json");
        response.setStatus(HttpServletResponse.SC_OK);
        response.getOutputStream().println(JSONResult.fillResultString(500, "Internal Server Error!!!", JSONObject.NULL));
    }
}

class JWTAuthenticationFilter extends GenericFilterBean {

    @Override
    public void doFilter(ServletRequest request,
                         ServletResponse response,
                         FilterChain filterChain)
            throws IOException, ServletException {
        Authentication authentication = TokenAuthenticationService
                .getAuthentication((HttpServletRequest)request);

        SecurityContextHolder.getContext()
                .setAuthentication(authentication);
        filterChain.doFilter(request,response);
    }
}


class AccountCredentials {

    private String username;
    private String password;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}

class GrantedAuthorityImpl implements GrantedAuthority{
    private String authority;

    public GrantedAuthorityImpl(String authority) {
        this.authority = authority;
    }

    public void setAuthority(String authority) {
        this.authority = authority;
    }

    @Override
    public String getAuthority() {
        return this.authority;
    }
}
