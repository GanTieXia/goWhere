package com.ruoyi.auth.service;

import cn.hutool.extra.mail.MailUtil;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.ruoyi.auth.util.RedisUtils;
import com.ruoyi.common.core.web.domain.AjaxResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import com.ruoyi.common.core.constant.Constants;
import com.ruoyi.common.core.constant.SecurityConstants;
import com.ruoyi.common.core.constant.UserConstants;
import com.ruoyi.common.core.domain.R;
import com.ruoyi.common.core.enums.UserStatus;
import com.ruoyi.common.core.exception.ServiceException;
import com.ruoyi.common.core.utils.ServletUtils;
import com.ruoyi.common.core.utils.StringUtils;
import com.ruoyi.common.core.utils.ip.IpUtils;
import com.ruoyi.common.security.utils.SecurityUtils;
import com.ruoyi.system.api.RemoteLogService;
import com.ruoyi.system.api.RemoteUserService;
import com.ruoyi.system.api.domain.SysLogininfor;
import com.ruoyi.system.api.domain.SysUser;
import com.ruoyi.system.api.model.LoginUser;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * 登录校验方法
 * 
 * @author ruoyi
 */
@Component
public class SysLoginService
{
    private static final Logger log = LoggerFactory.getLogger(SysLoginService.class);

    @Autowired
    private RemoteLogService remoteLogService;

    @Autowired
    private RemoteUserService remoteUserService;

    @Autowired
    private RedisUtils redisUtils;

    @Autowired
    private RabbitTemplate rabbitTemplate;

    @Value("${auth.loginQueueName}")
    private String loginQueueName;

    /**
     * 登录
     */
    public LoginUser login(String username, String password)
    {
        // 用户名或密码为空 错误
        if (StringUtils.isAnyBlank(username, password))
        {
            recordLogininfor(username, Constants.LOGIN_FAIL, "用户/密码必须填写");
            throw new ServiceException("用户/密码必须填写");
        }
        // 密码如果不在指定范围内 错误
        if (password.length() < UserConstants.PASSWORD_MIN_LENGTH
                || password.length() > UserConstants.PASSWORD_MAX_LENGTH)
        {
            recordLogininfor(username, Constants.LOGIN_FAIL, "用户密码不在指定范围");
            throw new ServiceException("用户密码不在指定范围");
        }
        // 用户名不在指定范围内 错误
        if (username.length() < UserConstants.USERNAME_MIN_LENGTH
                || username.length() > UserConstants.USERNAME_MAX_LENGTH)
        {
            recordLogininfor(username, Constants.LOGIN_FAIL, "用户名不在指定范围");
            throw new ServiceException("用户名不在指定范围");
        }
        // 查询用户信息
        R<LoginUser> userResult = remoteUserService.getUserInfo(username, SecurityConstants.INNER);

        if (R.FAIL == userResult.getCode())
        {
            throw new ServiceException(userResult.getMsg());
        }

        if (StringUtils.isNull(userResult) || StringUtils.isNull(userResult.getData()))
        {
            recordLogininfor(username, Constants.LOGIN_FAIL, "登录用户不存在");
            throw new ServiceException("登录用户：" + username + " 不存在");
        }
        LoginUser userInfo = userResult.getData();
        SysUser user = userResult.getData().getSysUser();
        if (UserStatus.DELETED.getCode().equals(user.getDelFlag()))
        {
            recordLogininfor(username, Constants.LOGIN_FAIL, "对不起，您的账号已被删除");
            throw new ServiceException("对不起，您的账号：" + username + " 已被删除");
        }
        if (UserStatus.DISABLE.getCode().equals(user.getStatus()))
        {
            recordLogininfor(username, Constants.LOGIN_FAIL, "用户已停用，请联系管理员");
            throw new ServiceException("对不起，您的账号：" + username + " 已停用");
        }
        if (!SecurityUtils.matchesPassword(password, user.getPassword()))
        {
            recordLogininfor(username, Constants.LOGIN_FAIL, "用户密码错误");
            throw new ServiceException("用户不存在/密码错误");
        }
        recordLogininfor(username, Constants.LOGIN_SUCCESS, "登录成功");
        // 用户登录后向MQ发送消息队列
        rabbitTemplate.convertAndSend(loginQueueName,"{\"username\"+\""+ username + "\"}");
        return userInfo;
    }

    public void logout(String loginName)
    {
        recordLogininfor(loginName, Constants.LOGOUT, "退出成功");
    }

    /**
     * 注册
     */
    public void register(String username, String password, String email, String emailCode)
    {
        // 用户名或密码为空 错误
        if (StringUtils.isAnyBlank(username, password))
        {
            throw new ServiceException("用户/密码必须填写");
        }
        if (username.length() < UserConstants.USERNAME_MIN_LENGTH
                || username.length() > UserConstants.USERNAME_MAX_LENGTH)
        {
            throw new ServiceException("账户长度必须在2到20个字符之间");
        }
        if (password.length() < UserConstants.PASSWORD_MIN_LENGTH
                || password.length() > UserConstants.PASSWORD_MAX_LENGTH)
        {
            throw new ServiceException("密码长度必须在5到20个字符之间");
        }

        // 用户名唯一性校验
        R<Map<String,String>> r = remoteUserService.getUserId(username,SecurityConstants.INNER);
        Map<String, String> rMap = r.getData();
        if(StringUtils.isNotEmpty(rMap.get("userId"))){
            throw new ServiceException("用户名已被占用");
        }

        // 邮箱验证
        String check = "(([^<>()\\[\\]\\\\.,;:\\s@\"]+(\\.[^<>()\\[\\]\\\\.,;:\\s@\"]+)*)|(\".+\"))@((\\[[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}])|(([a-zA-Z\\-0-9]+\\.)+[a-zA-Z]{2,}))";
        if(!email.matches(check)){
            throw new ServiceException("邮箱格式错误");
        }
        // 邮箱验证码验证
        String code = redisUtils.get(email);
        if(!emailCode.equals(code)){
            throw new ServiceException("邮箱验证码错误或失效，请重新发送");
        }
        // 注册用户信息
        SysUser sysUser = new SysUser();
        sysUser.setUserName(username);
        sysUser.setNickName(username);
        sysUser.setPassword(SecurityUtils.encryptPassword(password));
        sysUser.setEmail(email);
        R<?> registerResult = remoteUserService.registerUserInfo(sysUser, SecurityConstants.INNER);

        // 找到用户ID
        R<Map<String,String>> result = remoteUserService.getUserId(username,SecurityConstants.INNER);
        Map<String, String> resultCheckMap = result.getData();
        String userId = resultCheckMap.get("userId");
        // 默认角色为普通角色
        R<Map<String,String>> resultThis = remoteUserService.setUserRole(userId,SecurityConstants.INNER);
        Map<String, String> resultThisMap = resultThis.getData();
        if(!"200".equals(resultThisMap.get("code"))){
            throw new ServiceException("网络波动，请稍后再试...");
        }

        if (R.FAIL == registerResult.getCode())
        {
            throw new ServiceException(registerResult.getMsg());
        }
        recordLogininfor(username, Constants.REGISTER, "注册成功");
    }

    /**
     * 记录登录信息
     * 
     * @param username 用户名
     * @param status 状态
     * @param message 消息内容
     * @return
     */
    public void recordLogininfor(String username, String status, String message)
    {
        SysLogininfor logininfor = new SysLogininfor();
        logininfor.setUserName(username);
        logininfor.setIpaddr(IpUtils.getIpAddr(ServletUtils.getRequest()));
        logininfor.setMsg(message);
        // 日志状态
        if (StringUtils.equalsAny(status, Constants.LOGIN_SUCCESS, Constants.LOGOUT, Constants.REGISTER))
        {
            logininfor.setStatus(Constants.LOGIN_SUCCESS_STATUS);
        }
        else if (Constants.LOGIN_FAIL.equals(status))
        {
            logininfor.setStatus(Constants.LOGIN_FAIL_STATUS);
        }
        remoteLogService.saveLogininfor(logininfor, SecurityConstants.INNER);
    }

    /**
     * 发送验证码
     *
     * @param email
     * @return
     */
    public R<Object> sendCheckCode(String email){
        // 返回结果集
        Map<String,String> resultMap = new HashMap<>();
        // 查询是否已经发送验证码
        String checkCode = redisUtils.get(email);
        if(!StringUtils.isEmpty(checkCode)){
            resultMap.put("code","404");
            resultMap.put("msg","已发送验证码，请勿重复发送...");
            return R.ok(resultMap);
        }
        // 查询数据库中是否存在此邮箱
        R<Map<String,String>> result = remoteUserService.checkEmail(email,SecurityConstants.FROM_SOURCE);
        Map<String, String> resultCheckMap = result.getData();
        if(!"200".equals(resultCheckMap.get("code"))){
            resultMap.put("code","405");
            resultMap.put("msg","此邮箱已被绑定，请确认邮箱是否输入有误！");
            return R.ok(resultMap);
        }
        // 校验通过发送验证码
        log.info("开始发送验证码......");
        // 生成6位随机邮件验证码
        StringBuffer authCodes = new StringBuffer();
        for(int j = 0; j< 6; j++){
            authCodes.append((int)((Math.random()*10)));
        }
        // 发送验证码
        MailUtil.send(email, "验证码信息", "<br>您的注册验证码为: <label style=\"color: red\"> " + authCodes + "</label> <br>请妥善保管，防止丢失！<br>如不是您本人操作，请忽略！", true);
        // 将验证码存入redis并设置三分钟失效时间
        redisUtils.setKeyTimeOut(email,String.valueOf(authCodes),180, TimeUnit.SECONDS);
        log.info("验证码发送成功......");
        resultMap.put("code","200");
        resultMap.put("msg","验证码发送成功！");
        return R.ok(resultMap);
    }

    /**
     * 校验输入验证码的正确性
     *
     * @param emailInfo
     * @return
     */
    public R<Object> checkCode(String emailInfo){
        Map<String,String> messageMap = (Map) JSON.parse(emailInfo);
        String email = messageMap.get("email");
        String emailCode = messageMap.get("emailCode");
        // 返回结果集
        Map<String,String> resultMap = new HashMap<>();
        // 从Redis中获取验证码
        String code = redisUtils.get(email);
        // 校验
        // 如果为空，则未发送验证码
        if(!emailCode.equals(code)){
            resultMap.put("code","404");
            resultMap.put("msg","邮箱验证码错误！");
            return R.ok(resultMap);
        }
        resultMap.put("code","200");
        resultMap.put("msg","邮箱验证通过！");
        return R.ok(resultMap);
    }
}