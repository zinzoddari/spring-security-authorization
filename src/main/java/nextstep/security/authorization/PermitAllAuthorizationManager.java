package nextstep.security.authorization;

import nextstep.security.authentication.Authentication;

public class PermitAllAuthorizationManager implements AuthorizationManager<Void> {

    @Override
    public AuthorizationDecision check(Authentication authentication, Void object) {
        return new AuthorizationDecision(true);
    }
}
