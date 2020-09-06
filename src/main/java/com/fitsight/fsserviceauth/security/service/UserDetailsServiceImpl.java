package com.fitsight.fsserviceauth.security.service;

import com.fitsight.fsserviceauth.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
  @Autowired
  MongoTemplate mongoTemplate;

  public UserDetails loadUserByEmail(String email) throws UsernameNotFoundException {
    User user = mongoTemplate.findOne(Query.query(Criteria.where("email").is(email)), User.class);
    return UserDetailsImpl.build(user);
  }

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    return loadUserByEmail(username);
  }
}
