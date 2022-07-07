package com.ruoyi.system.api;

import com.ruoyi.common.core.web.domain.AjaxResult;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import com.ruoyi.common.core.constant.SecurityConstants;
import com.ruoyi.common.core.constant.ServiceNameConstants;
import com.ruoyi.common.core.domain.R;
import com.ruoyi.system.api.domain.SysUser;
import com.ruoyi.system.api.factory.RemoteUserFallbackFactory;
import com.ruoyi.system.api.model.LoginUser;

import java.util.Map;

/**
 * 用户服务
 * 
 * @author ruoyi
 */
@FeignClient(contextId = "remoteUserService", value = ServiceNameConstants.SYSTEM_SERVICE, fallbackFactory = RemoteUserFallbackFactory.class)
public interface RemoteUserService
{
    /**
     * 通过用户名查询用户信息
     *
     * @param username 用户名
     * @param source 请求来源
     * @return 结果
     */
    @GetMapping("/user/info/{username}")
    R<LoginUser> getUserInfo(@PathVariable("username") String username, @RequestHeader(SecurityConstants.FROM_SOURCE) String source);

    /**
     * 注册用户信息
     *
     * @param sysUser 用户信息
     * @param source 请求来源
     * @return 结果
     */
    @PostMapping("/user/register")
    R<Boolean> registerUserInfo(@RequestBody SysUser sysUser, @RequestHeader(SecurityConstants.FROM_SOURCE) String source);

    /**
     * 校验邮箱
     *
     * @param email
     * @param source
     * @return
     */
    @PostMapping("/user/checkEmail")
    R<Map<String,String>> checkEmail(@RequestBody String email, @RequestHeader(SecurityConstants.FROM_SOURCE) String source);

    /**
     * 设置默认角色
     *
     * @param userId
     * @param source
     * @return
     */
    @PostMapping("/user/setUserRole")
    R<Map<String,String>> setUserRole(@RequestBody String userId, @RequestHeader(SecurityConstants.INNER) String source);

    /**
     * 通过用户名找到userId
     *
     * @param userName
     * @param source
     * @return
     */
    @PostMapping("/user/getUserId")
    R<Map<String,String>> getUserId(@RequestBody String userName, @RequestHeader(SecurityConstants.INNER) String source);



}
