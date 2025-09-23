//package com.example.userservice.config;
//
//import org.springframework.amqp.core.*;
//import org.springframework.amqp.rabbit.connection.ConnectionFactory;
//import org.springframework.amqp.rabbit.core.RabbitTemplate;
//import org.springframework.amqp.support.converter.Jackson2JsonMessageConverter;
//import org.springframework.amqp.support.converter.MessageConverter;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//
//@Configuration
//public class UserRabbitConfig {
//
//    public static final String EXCHANGE = "user-exchange";
//    public static final String USER_QUEUE = "user-queue";
//    public static final String ROUTING_KEY_USER_EVENT = "user.event";
//
//    @Bean
//    public Queue userQueue() {
//        return new Queue(USER_QUEUE, true);
//    }
//
//    @Bean
//    public TopicExchange userExchange() {
//        return new TopicExchange(EXCHANGE);
//    }
//
//    @Bean
//    public Binding bindingUser() {
//        return BindingBuilder.bind(userQueue()).to(userExchange()).with(ROUTING_KEY_USER_EVENT);
//    }
//
//    @Bean
//    public MessageConverter jsonMessageConverter() {
//        return new Jackson2JsonMessageConverter();
//    }
//
//    @Bean
//    public AmqpTemplate rabbitTemplate(ConnectionFactory connectionFactory) {
//        RabbitTemplate rabbitTemplate = new RabbitTemplate(connectionFactory);
//        rabbitTemplate.setMessageConverter(jsonMessageConverter());
//        return rabbitTemplate;
//    }
//}
