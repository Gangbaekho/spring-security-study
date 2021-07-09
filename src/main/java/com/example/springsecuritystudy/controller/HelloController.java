package com.example.springsecuritystudy.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping("/hello")
    public String hello(){

        return "Spring security study";
    }

    @GetMapping("/bye")
    public String bye(){

        return "Get lost!!";
    }
}
