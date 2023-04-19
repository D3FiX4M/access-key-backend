package com.example.accesskeybackend.template.service;

import com.example.accesskeybackend.exception.IllegalArgumentException;
import com.example.accesskeybackend.exception.NotFoundException;
import lombok.SneakyThrows;
import org.springframework.stereotype.Service;

import javax.naming.NamingEnumeration;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class CheckIpV6SupportService {

    private static final String DNS_ADDRESS_GOOGLE_V1 = "8.8.8.8";

    private HashMap<String, Object> createEnv() {
        return new HashMap<>() {{
            put(
                    "java.naming.factory.initial",
                    "com.sun.jndi.dns.DnsContextFactory"
            );
            put(
                    "java.naming.provider.url",
                    "dns://" + DNS_ADDRESS_GOOGLE_V1
            );
        }};
    }

    enum Specification {
        A,
        NS,
        CNAME,
        SOA,
        PTR,
        MX,
        TXT,
        HINFO,
        AAAA,
        NAPTR,
        SRV;

        private static Specification getByName(String org) {
            for (Specification value : values()) {
                if (value.name()
                        .equalsIgnoreCase(org.trim())) {
                    return value;
                }
            }
            throw new NotFoundException("Not found Specification: " + org);
        }
    }

    public String convertURItoDomain(String url) {
        Pattern pattern = Pattern.compile("^(?:https?:\\/\\/)?(?:[^@\\n]+@)?(?:www\\.)?([^:\\/\\n]+)");
        Matcher matcher = pattern.matcher(url);
        if (matcher.find()) {
            return matcher.group(1);
        } else {
            throw new IllegalArgumentException("Bad URI:" + url);
        }
    }


    @SneakyThrows
    public boolean checkIpV6(String url) {

        String domain = convertURItoDomain(url);

        final NamingEnumeration<? extends Attribute> dnsInfo = getDnsInfo(
                domain,
                createEnv()
        );

        final Map<Specification, String> convert = convert(dnsInfo);
        return convert.containsKey(Specification.AAAA);
    }

    @SneakyThrows
    private Map<Specification, String> convert(NamingEnumeration<? extends Attribute> dnsInfo) {
        Map<Specification, String> result = new HashMap<>();
        while (dnsInfo.hasMoreElements()) {
            Attribute a = dnsInfo.next();
            result.put(
                    Specification.getByName(a.getID()),
                    a.get()
                            .toString()
            );
        }
        return result;
    }

    @SneakyThrows
    private NamingEnumeration<? extends Attribute> getDnsInfo(
            String domain,
            HashMap<String, Object> env
    ) {
        DirContext dirContext = new InitialDirContext(hashMapToHashTable(env));

        Attributes attrs = dirContext.getAttributes(
                domain,
                new String[]{Specification.AAAA.name()}
        );

        return attrs.getAll();
    }

    private Hashtable<String, Object> hashMapToHashTable(HashMap<String, Object> map) {
        return new Hashtable<>(map);
    }
}
