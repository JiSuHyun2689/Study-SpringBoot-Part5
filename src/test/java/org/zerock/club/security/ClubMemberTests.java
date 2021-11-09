package org.zerock.club.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.zerock.club.entity.ClubMember;
import org.zerock.club.entity.ClubMemberRole;
import org.zerock.club.repository.ClubMemberRepository;

import javax.swing.text.html.Option;
import java.util.Optional;
import java.util.stream.IntStream;

@SpringBootTest
public class ClubMemberTests {

    @Autowired
    private ClubMemberRepository repository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    public void insertDummies(){

        // 1 - 80 : USER
        // 81 - 90 : USER, MANAGER
        // 91 - 100 : USER, MANAGER, ADMIN
        IntStream.rangeClosed(1, 100).forEach(i ->{
            ClubMember clubMember = ClubMember.builder().email("user"+i+"@aaaa.com")
                    .name("사용자" + i).fromSocial(false).password(passwordEncoder.encode("1111")).build();

            // default role
            clubMember.addMemberRole(ClubMemberRole.USER);

            if(i > 80)
                clubMember.addMemberRole(ClubMemberRole.MANAGER);
            if(i > 90)
                clubMember.addMemberRole(ClubMemberRole.ADMIN);

            repository.save(clubMember);

        });

    }

    @Test
    public void testRead(){

        Optional<ClubMember> result = repository.findByEmail("user95@aaaa.com", false);
        ClubMember clubMember = result.get();
        System.out.println(clubMember);
    }
}
