package com.inmaytide.orbit.authorization;

import com.inmaytide.orbit.commons.utils.CodecUtils;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * @author inmaytide
 * @since 2025/7/15
 */
public class PasswordEncodeTester {

    public static void main(String[] args) throws Exception {
        String password = "111111";
        String encrypted = CodecUtils.encrypt(password);
        String encoded = new BCryptPasswordEncoder().encode(password);

        System.out.println("Raw password: " + password);
        System.out.println("Encrypted password: " + encrypted);
        System.out.println("Encoded Password: " + encoded);
    }

}
