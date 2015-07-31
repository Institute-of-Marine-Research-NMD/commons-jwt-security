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
 * Generic access descrision voter.
 *
 * @author kjetilf
 */
@Service
public class UrlAccessDecisionVoter implements AccessDecisionVoter<FilterInvocation> {
    /**
     * Read access role.
     */
    private final String readRole;
    /**
     * Write access role.
     */
    private final String writeRole;
    /**
     * Regexp used to filter url requests.
     */
    private final String urlRegexp;

    /**
     * Initialize.
     *
     * @param readRole  Read access role required.
     * @param writeRole Write access role.
     */
    public UrlAccessDecisionVoter(final String readRole, final String writeRole, final String urlRegexp) {
        this.readRole = readRole;
        this.writeRole = writeRole;
        this.urlRegexp = urlRegexp;
    }

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
        if (obj.getFullRequestUrl().matches(urlRegexp)) {
            if (obj.getHttpRequest().getMethod().equalsIgnoreCase(HttpMethod.GET.name()) || obj.getHttpRequest().getMethod().equalsIgnoreCase(HttpMethod.HEAD.name())) {
                if (auth.isAuthenticated() && auth.getAuthorities().contains(new SimpleGrantedAuthority(this.readRole))) {
                    return ACCESS_GRANTED;
                } else {
                    return ACCESS_DENIED;
                }
            } else {
                if (auth.isAuthenticated() && auth.getAuthorities().contains(new SimpleGrantedAuthority(this.writeRole))) {
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
