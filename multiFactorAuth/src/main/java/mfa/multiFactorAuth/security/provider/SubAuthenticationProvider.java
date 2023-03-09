package mfa.multiFactorAuth.security.provider;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import mfa.multiFactorAuth.security.service.FormUserDetailsService;
import mfa.multiFactorAuth.security.token.MfaAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Slf4j
@RequiredArgsConstructor
public class SubAuthenticationProvider implements AuthenticationProvider {

    private final PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String pin = (String)authentication.getCredentials();
        if(!pin.equals("1234")) {
            throw new BadCredentialsException("BadCredential Exception");
        }


        MfaAuthenticationToken authenticationToken = (MfaAuthenticationToken)SecurityContextHolder
                                                .getContext().getAuthentication();
        authenticationToken.increaseAuthLevel();
        log.info("2nd authentication end");
        return authenticationToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
