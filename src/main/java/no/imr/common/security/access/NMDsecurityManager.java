package no.imr.common.security.access;

import java.util.List;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.UnanimousBased;

/**
 * Access manager for the nmd api. We use a unanimous based voter.
 *
 * Defined use is in WebSucurity configuration.
 *
 * @author kjetilf
 */
public class NMDsecurityManager extends UnanimousBased {

    /**
     *
     * @param decisionVoters    Descision voters.
     */
    public NMDsecurityManager(List<AccessDecisionVoter<? extends Object>> decisionVoters) {
        super(decisionVoters);
    }

    @Override
    public boolean isAllowIfAllAbstainDecisions() {
        return false;
    }

}
