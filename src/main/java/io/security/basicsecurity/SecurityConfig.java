package io.security.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity
@Order(0)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsService userDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        /*
        * roles에는 여러개의 그룹들이 들어 갈 수 있고 하단에 기술된 roles와 같이 여러개 기술이 가능하다.
        * */
        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS", "USER");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN", "SYS", "USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        /*
        * 인가 api 권한 설정중 antPatterns은 상세한 패턴이 상단이 오게 만들어야 함.
        * ex) /admin/pay 와 /admin/** 이 있을경우 /admin/pay가 /admin/** 보다 상위라인에 기술되어야 함.
        * */
//        http.authorizeRequests()
//                .antMatchers("/login").permitAll()
//                .antMatchers("/user").hasRole("USER")
//                .antMatchers("/admin/pay").hasRole("ADMIN")
//                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
//                .anyRequest()
//                .fullyAuthenticated();


        http.antMatcher("/admin/**")
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .httpBasic();

        http.formLogin() //로그인 관련 설정
                //.loginPage("/loginPage") //직접 로그인 페이지 설정.

                // 인증, 인가예외 처리 부분
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        RequestCache requestCache = new HttpSessionRequestCache();
                        SavedRequest savedRequest = requestCache.getRequest(request, response);
                        String redirectUrl = savedRequest.getRedirectUrl();
                        response.sendRedirect(redirectUrl);
                    }
                })

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

        http.sessionManagement()
                .maximumSessions(1) //한 아이디에 한꺼번에 접속가능한 수 (세션의 수)
                .maxSessionsPreventsLogin(false); //flase시 이전사용자의 세션 무효화, true시 신규사용자의 세션생성 차단. 기본값은 false.

        http.sessionManagement()
                .sessionFixation().changeSessionId(); //세션 탈취 방지 로그인시 세션 ID가 변경됨.


        /*
        * 인증, 인가예외 처리 핸들러 부분.
        * */
        http.exceptionHandling() //예외처리 핸들러
                .authenticationEntryPoint(new AuthenticationEntryPoint() { // 인증예외시 핸들러
                    @Override
                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                })
                .accessDeniedHandler(new AccessDeniedHandler() { //인가예외시 핸들러
                    @Override
                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                        response.sendRedirect("/denied");
                    }
                });

        /*
        * csrf 대한부분은 기본적으로 활성화 되어 있음.
        * 다음과 같이 disable() 메소드로 비활성화 가능함.
        * csrf 필터는 켜두는것을 보안상 권장함.
        * 그래서 일단 하단에 주석처리 해둠.
        * */
        // http.csrf().disable();
    }
}

@Configuration
@Order(1) //Order가 0번째 부터 받아옴.
class SercurityConfig2 extends WebSecurityConfigurerAdapter{

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().permitAll()
                .and()
                .formLogin();
    }
}
