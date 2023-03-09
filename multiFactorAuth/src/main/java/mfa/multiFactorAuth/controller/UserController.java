package mfa.multiFactorAuth.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@Slf4j
public class UserController {

    @GetMapping("/login")
    public String do1stLogin() {
        return "login";
    }
    @GetMapping("/second-login")
    public String do2ndLogin() {
        return "second-login";
    }
}
