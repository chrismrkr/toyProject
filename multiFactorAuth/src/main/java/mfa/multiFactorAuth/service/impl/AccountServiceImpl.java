package mfa.multiFactorAuth.service.impl;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import mfa.multiFactorAuth.domain.Account;
import mfa.multiFactorAuth.repository.AccountRepository;
import mfa.multiFactorAuth.service.AccountService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;

@Service("accountService")
@Slf4j
@RequiredArgsConstructor
public class AccountServiceImpl implements AccountService {
    private final AccountRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @PostConstruct
    void saveUser() {
        Account account = Account.builder().username("user")
                .password(passwordEncoder.encode("1111"))
                .age(28)
                .build();
        userRepository.save(account);
    }
}
