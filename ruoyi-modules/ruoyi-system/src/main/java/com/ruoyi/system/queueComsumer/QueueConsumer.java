package com.ruoyi.system.queueComsumer;

import cn.hutool.extra.mail.MailUtil;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.ruoyi.system.api.domain.SysUser;
import com.ruoyi.system.mapper.SysUserMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * 用于给登录用户发送上线邮件
 *
 * @author DengHaiLin
 * @date 2022/11/22 11:18
 */
@Component
@Slf4j
public class QueueConsumer {

    @Autowired
    private SysUserMapper sysUserMapper;

    /**
     * 消费用户登录后的消息
     *
     * @param msg JSON消息体
     */
    @RabbitListener(queues = "auth.loginQueue")
    public void listenQueue(String msg){
        // 解析消息
        JSONObject prams = JSON.parseObject(msg);
        // 获取用户名
        String userName = prams.getString("userName");
        log.info("=========解析后的消息=========");
        log.info("userName:" + userName);
        // 给用户发送邮件提示已登录系统
        SysUser sysUser = sysUserMapper.selectUserByUserName(userName);
        String email = sysUser.getEmail();
        // 执行发送邮件操作
        // 发送验证码
        MailUtil.send(email, "去哪儿系统登录提示", "<br>亲爱的用户: <label style=\"color: red\"> " +
                userName + "</label> 您已登录 www.hailin.pro 去哪儿网！<br>", true);

    }
}
