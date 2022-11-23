package com.ruoyi.system.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * @author DengHaiLin
 * @date 2022/11/23 15:24
 */
@RestController
@RequestMapping("/countSys")
public class CountSysLoginController {

    /**
     * 获取系统统计数量
     */
    @GetMapping("/countSysLogin")
    public Map<String,Object> countSysLogin() {
        Map<String,Object> map = new HashMap<>();
        map.put("sysLogin","2022");
        return map;
    }
}
