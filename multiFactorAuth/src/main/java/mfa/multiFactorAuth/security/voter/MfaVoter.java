package mfa.multiFactorAuth.security.voter;

import mfa.multiFactorAuth.security.token.MfaAuthenticationToken;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.vote.AbstractAccessDecisionManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;

import java.util.Collection;
import java.util.List;

public class MfaVoter extends AbstractAccessDecisionManager {

    public MfaVoter(List<AccessDecisionVoter<?>> decisionVoters) {
        super(decisionVoters);
    }

    @Override
    @SuppressWarnings({ "rawtypes", "unchecked" })
    public void decide(Authentication authentication, Object object, Collection<ConfigAttribute> configAttributes)
            throws AccessDeniedException {
        /* 인증 단계 확인 */
        FilterInvocation filterInvocation = (FilterInvocation)object;
        if(filterInvocation.getRequestUrl().equals("/login")) { // 임시코드. 이 부분 securityMetaSource 생성하면서 제거함
            return;
        }

        if(authentication instanceof MfaAuthenticationToken) {
            if(((MfaAuthenticationToken)authentication).getAuthLevel() == 1) {
                if (filterInvocation.getRequestUrl().equals("/second-login")) {
                    return;
                } else {
                    throw new AccessDeniedException(this.messages.getMessage("AbstractAccessDecisionManager.accessDenied", "Access is denied"));
                }
            }
            else {
                return;
            }
        }

        int deny = 0;
        for (AccessDecisionVoter voter : getDecisionVoters()) {
            int result = voter.vote(authentication, object, configAttributes);
            switch (result) {
                case AccessDecisionVoter.ACCESS_GRANTED:
                    return;
                case AccessDecisionVoter.ACCESS_DENIED:
                    deny++;
                    break;
                default:
                    break;
            }
        }
        if (deny > 0) {
            throw new AccessDeniedException(
                    this.messages.getMessage("AbstractAccessDecisionManager.accessDenied", "Access is denied"));
        }
        // To get this far, every AccessDecisionVoter abstained
        checkAllowIfAllAbstainDecisions();
    }

}
