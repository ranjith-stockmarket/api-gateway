package com.stockmarket.apigateway.Security;

import com.stockmarket.apigateway.JWT.JwtRequestFilter;
import com.stockmarket.apigateway.UserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfigurer extends WebSecurityConfigurerAdapter {

    private final UserService userService;
    private final JwtRequestFilter jwtRequestFilter;

    public SecurityConfigurer(UserService userService, JwtRequestFilter jwtRequestFilter) {
        this.userService = userService;
        this.jwtRequestFilter = jwtRequestFilter;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userService);
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.csrf().disable()
//                .authorizeRequests()
//                .antMatchers("/api/access","/api/login","/api/image/get/*","/api/user/setPassword","/api/user/forgotPassword/*").permitAll()
//                .antMatchers("/api/admin-user/**","/api/admin-warehouse/**").hasRole("ADMIN")
//                .antMatchers("/api/user/**").hasRole("USER")
//                .antMatchers("/api/warehouse/**", "/api/warehouse-hub/**",
//                        "/api/procurement/**","/api/product/productGroup/abstract/all").hasAnyRole("WAREHOUSE", "ADMIN")
//                .antMatchers("/api/hub/**","/api/product/productGroup/abstract/master/all").hasAnyRole("HUB", "ADMIN")
//                .antMatchers("/api/product/**", "/api/image/add").hasAnyRole("PRODUCT", "ADMIN")
//                .antMatchers("/api/customer/**").hasAnyRole("CUSTOMER","ADMIN")
//                .anyRequest().authenticated()
//                .and()
//                .formLogin()
//                .loginPage("/api/access").permitAll()
//                .loginProcessingUrl("/api/login").permitAll()
//                .successForwardUrl("/api/login/success")
//                .failureForwardUrl("/api/login/fail").permitAll()
//                .and()
//                .logout()
//                .invalidateHttpSession(true)
//                .clearAuthentication(true)
//                .logoutRequestMatcher(new AntPathRequestMatcher("/api/logout"))
//                .logoutSuccessUrl("/api/logout/success").permitAll();
//    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests().antMatchers("/api/authenticate").permitAll()
                .anyRequest().authenticated()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
