package com.example.accesskeybackend.template.controller;

import com.example.accesskeybackend.template.service.CheckIpV6SupportService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class CheckIpv6SupportController {
    private final CheckIpV6SupportService checkIpv6SupportService;

    private static final String CHECK_IPV6_ROOT = "/api/web/checkIpv6Support";

    @GetMapping(CHECK_IPV6_ROOT)
    public boolean checkIpv6(@RequestParam String siteUrl) {
        return checkIpv6SupportService.checkIpV6(siteUrl);
    }
}
