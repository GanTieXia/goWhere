package com.ruoyi.auth;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.context.web.WebAppConfiguration;

/**
 * @author DengHaiLin
 * @date 2022/11/22 10:25
 */
@RunWith(SpringRunner.class)
@SpringBootTest
@WebAppConfiguration()
public class test {


    @Autowired
    private RabbitTemplate rabbitTemplate;

    @Value("${auth.loginQueueName}")
    private String queueName;

    @Test
    public void testQueue(){
        String message = "{\"userName\":\"admin\"}";
        rabbitTemplate.convertAndSend(queueName,message);
        System.out.println("消息发送成功");
    }
}
