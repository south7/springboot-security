package com.example.springbootsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    /**
     * 安全拦截机制
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/r/r1").hasAuthority("p1")
                .antMatchers("/r/r2").hasAuthority("p2")
                //所有/r/**的请求必须认证通过
                .antMatchers("/r/**").authenticated()
                //其他请求，放行
                .anyRequest().permitAll()
                .and()
                //允许表单登录
                .formLogin()
                //登录成功后访问地址
                .successForwardUrl("/login-success");
    }

    /**
     * 定义用户信息服务
     *
     * @return InMemoryUserDetailsManager对象
     */
    @Bean
    public UserDetailsService userDetailsService(){
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(User.withUsername("zs").password("1").authorities("p1").build());
        manager.createUser(User.withUsername("ls").password("1").authorities("p2").build());
        return manager;
    }

    /**
     * 密码编码器
     *
     * @return PasswordEncoder对象
     */
    @Bean
    public PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }


}
