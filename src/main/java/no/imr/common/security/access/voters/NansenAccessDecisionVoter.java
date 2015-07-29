package no.imr.common.security.access.voters;

import java.util.Collection;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.AccessDecisionVoter;
import static org.springframework.security.access.AccessDecisionVoter.ACCESS_ABSTAIN;
import static org.springframework.security.access.AccessDecisionVoter.ACCESS_DENIED;
import static org.springframework.security.access.AccessDecisionVoter.ACCESS_GRANTED;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.FilterInvocation;
import org.springframework.stereotype.Service;

/**
 * Access decision voter for biotic data. As all data is standard available this
 * voter always returns access.
 *
 * @author kjetilf
 */
@Service
public class NansenAccessDecisionVoter implements AccessDecisionVoter<FilterInvocation> {

    /**
     * Role to have to gain read access to Nansen data.
     */
    public static final String ROLE_READ_ACCESS = "SG-NMD-NANSEN-READ";
    /**
     * Role to have to gain write access to Nansen data.
     */
    public static final String ROLE_WRITE_ACCESS = "SG-NMD-NANSEN-WRITE";

    /**
     * Regular expression used to identify Nansen data by it's url.
     */
    public static final String REGEXP_NANSEN_URL = ".+/[0-9]*?/[0-9]{4}/1172/[0-9]*?";

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return clazz.isAssignableFrom(FilterInvocation.class);
    }

    @Override
    public int vote(Authentication auth, FilterInvocation obj, Collection<ConfigAttribute> confAttrs) {
        if (obj.getFullRequestUrl().matches(REGEXP_NANSEN_URL)) {
            if (obj.getHttpRequest().getMethod().equalsIgnoreCase(HttpMethod.GET.name()) || obj.getHttpRequest().getMethod().equalsIgnoreCase(HttpMethod.HEAD.name())) {
                if (auth.isAuthenticated() && auth.getAuthorities().contains(new SimpleGrantedAuthority(NansenAccessDecisionVoter.ROLE_READ_ACCESS))) {
                    return ACCESS_GRANTED;
                } else {
                    return ACCESS_DENIED;
                }
            } else {
                if (auth.isAuthenticated() && auth.getAuthorities().contains(new SimpleGrantedAuthority(NansenAccessDecisionVoter.ROLE_WRITE_ACCESS))) {
                    return ACCESS_GRANTED;
                } else {
                    return ACCESS_DENIED;
                }
            }
        } else {
            // Not reference data.
            return ACCESS_ABSTAIN;
        }
    }

}
