package com.amrit.apigateway.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class TestController {


    @GetMapping("/profile")
    public String profile(
            Authentication authentication
    ) {

        return "Authenticated user: "
                + authentication.getName();
    }


    @GetMapping("/developer/test")
    public String developer() {

        return "Developer API is working";
    }


    @GetMapping("/admin/test")
    public String admin() {

        return "Admin API is working";
    }

}