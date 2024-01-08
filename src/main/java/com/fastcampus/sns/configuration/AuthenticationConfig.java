package com.fastcampus.sns.configuration;

import com.fastcampus.sns.configuration.filter.JwtTokenFilter;
import com.fastcampus.sns.exception.CustomAuthenticationEntryPoint;
import com.fastcampus.sns.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class AuthenticationConfig {


    private final UserService userService;
    @Value("${jwt.secret-key}")
    private String key;

    //WebSecurityConfigurerAdapter 권장방식 변경으로 인한 코드변경
    //[출처] https://uriu.tistory.com/435
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws  Exception{
        http.httpBasic(HttpBasicConfigurer::disable)
                .csrf(CsrfConfigurer::disable)
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/api/*/users/join", "/api/*/users/login").permitAll()
                        .requestMatchers("/api/**").authenticated()
                )
                .sessionManagement(configurer -> configurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(new JwtTokenFilter(key, userService), UsernamePasswordAuthenticationFilter.class) //요청할때마다 토큰 값을 보고 유저 구분
                //TODO
                .exceptionHandling(authenticationManager -> authenticationManager
                        .authenticationEntryPoint(new CustomAuthenticationEntryPoint()))
                        //.accessDeniedHandler(new CustomAccessDeniedHandler()))
                ;
        return http.build();

        //강의에서 알려준 방식

        //http.csrf().disable()
        //http.authorizeHttpRequests()
        //        .requestMatchers("/api/*/users/join", "/api/*/users/login").permitAll()
        //       .requestMatchers("/api/**").authenticated()
        //        .and()
        //        .sessionManagement()
        //        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        //;
                //TODO
                //.exceptionHandling()
                //.authentionEntryPoint()
    }
}
