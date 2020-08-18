package io.security.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
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

    @Autowired
    UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest()
                .fullyAuthenticated();
        http.formLogin() //로그인 관련 설정
                //.loginPage("/loginPage") //직접 로그인 페이지 설정.
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
        *
        * +추가 코멘
        * 각 핸들러는 interface로 생성하여 다른파일에 정의가 가능함.
        * */
        http.logout() //로그아웃 관련 설정
                .logoutUrl("/logout") //일반적으로 POST 방식을 사용. GET방식 이용시 오류발생 할 수 있음.
                .logoutSuccessUrl("/login")
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate(); //세션 무효화
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/login"); //로그아웃후 리다이렉트
                    }
                })

                /*
                 * ## 쿠키 remember-me 관련 ##
                 * 쿠키의 라이프 사이클은 인증성공시 remember-me 쿠키가 설정됨
                 * 혹여 쿠키가 존재하며, 인증실패시 쿠키는 무효화가되고, 로그아웃시
                 * 마찬가지로 쿠키가 무효화가 됨.
                 * */
                .deleteCookies("remember-me"); // 아이디 기억(?)  자동로그인 (?) 서버에서 쿠키를 생성하므로, 로그인시 쿠키를 삭제

        http.rememberMe()
                .rememberMeParameter("remember") //체크박스와 같은 값을 줘야함.
                .tokenValiditySeconds(3600) //기본은 14일
                .alwaysRemember(true) //기본값은 false #remember-me 기능이 활성화되지 않아도 항상 실행
                .userDetailsService(userDetailsService);
    }
}
