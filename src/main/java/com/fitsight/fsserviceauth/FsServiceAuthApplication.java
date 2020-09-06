package com.fitsight.fsserviceauth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;

@EnableEurekaClient
@SpringBootApplication
public class FsServiceAuthApplication {

	public static void main(String[] args) {
		SpringApplication.run(FsServiceAuthApplication.class, args);
	}

}
