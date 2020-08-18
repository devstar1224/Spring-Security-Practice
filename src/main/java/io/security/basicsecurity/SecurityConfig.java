package io.security.basicsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest()
                .fullyAuthenticated();
        http.formLogin() //로그인 관련 설정
                // .loginPage("/loginPage") //직접 로그인 페이지 설정.
                .defaultSuccessUrl("/") //로그인이 성공하면 이동할 url
                .failureUrl("/login") //실패 했을때. 호출 url
                .usernameParameter("userId") //아이디 파라미터 설정
                .passwordParameter("passwd") //비밀번호 파라미터 설정
                .loginProcessingUrl("/login_proc") //form태그의 action url 역할.
                .successHandler(new AuthenticationSuccessHandler() { //성공했을때. 핸들러.
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        System.out.println("auth :" + authentication.getName());
                        response.sendRedirect("/");
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() { //실패했을때. 핸들러.
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("exception :" + exception.getMessage());
                        response.sendRedirect("/login");
                    }
                })
                .permitAll();

        /*
        * SecurityContextLogoutHandler가 세션을 무효화 시키고,
        * 쿠키를 삭제, SecurityContexHolder.clearContext()를 호출하여 로그아웃시킴
        * */

        http.logout() //로그아웃 관련 설정
                .logoutUrl("/logout") //일반적으로 POST 방식을 사용.
                .logoutSuccessUrl("/login")
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate();
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                })
                .deleteCookies("remember-me"); //서버에서 쿠키를 생성하므로, 로그인시 쿠키를 삭제
    }
}