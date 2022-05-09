package io.ysf.springsecurityjwt;

//@EnableWebSecurity
public class MySecurityConfigureAdapter {
//	extends WebSecurityConfigurerAdapter {
//	@Autowired
//	MyUserDetailsService myUserDetailsService;
//
//	@Override
//	protected void configure(AuthenticationManagerBuilder auth)
//			throws Exception {
//		auth.userDetailsService(myUserDetailsService);
//		// auth.inMemoryAuthentication().withUser("user")
//		// .password("{noop}password").roles("USER").and()
//		// .withUser("admin").password("{noop}password").roles("ADMIN");
//	}
//
//	@Override
//	protected void configure(HttpSecurity http) throws Exception {
//		http.csrf().disable().authorizeRequests().antMatchers("/authenticate")
//				.permitAll().anyRequest().authenticated();
//	}
//
//	@Override
//	@Bean
//	public AuthenticationManager authenticationManagerBean() throws Exception {
//		return super.authenticationManager();
//	}
//
//	@Bean
//	public PasswordEncoder getPasswordEncoder() {
//		return NoOpPasswordEncoder.getInstance();
//	}
//
}
