package org.scribe.extractors;

import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.scribe.exceptions.OAuthException;
import org.scribe.model.Token;
import org.scribe.utils.Preconditions;

/**
 * Extractor for Force.com OAuth tokens.
 *
 * @author Tim Kral, Ryan Shillington
 */
public class ForceTokenExtractor implements AccessTokenExtractor
{

    private Pattern forceTokenPattern =
            Pattern.compile("\"id\":\"(\\S*?)\",\"issued_at\":\"(\\d*?)\",\"scope\":\"(\\S*?)\","
                    + "\"instance_url\":\"(\\S*?)\",\"signature\":\"(\\S*?)\",\"access_token\":\"(\\S*?)\"");

    @Override
    public Token extract(String response)
    {
        Preconditions.checkEmptyString(response, "Cannot extract a token from a null or empty String");
        Matcher matcher = forceTokenPattern.matcher(response);
        if (matcher.find())
        {
            return new ForceToken(
                    matcher.group(1) /*id*/, matcher.group(2) /*issuedAt*/,
                    matcher.group(3) /*scope*/, matcher.group(4) /*instanceUrl*/,
                    matcher.group(5) /*signature*/, matcher.group(6) /*accessToken*/,
                    response);
        } else
        {
            throw new OAuthException("Cannot extract a Force.com access token. Response was: " + response);
        }
    }

    /**
     * Force.com OAuth token.
     * <p/>
     * This contains extra information from the Force.com OAuth service:
     * <ul>
     * <li>Id - A URL representing the authenticated Force.com user. This can be used to access Force.com's identity service</li>
     * <li>IssuedAt - The datetime stamp at which the token was issued by Force.com</li>
     * <li>InstanceUrl - The Force.com instance to which subsequent API calls should be sent</li>
     * <li>Signature - HMAC-SHA256 hash for the Id and IssuedAt state</li>
     * </ul>
     *
     * @author Tim Kral, Ryan Shillington
     */
    public static class ForceToken extends Token
    {

        private static final long serialVersionUID = -1522491125878959187L;

        private final String id;
        private final Date issuedAt;
        private final String scope;
        private final String instanceUrl;
        private final String signature;

        public ForceToken(String id, String issuedAtStr, String scope, String instanceUrl, String signature,
                          String token, String rawResponse)
        {
            super(token, token, rawResponse);
            this.scope = scope;
            this.id = id;
            this.issuedAt = new Date(Long.parseLong(issuedAtStr));
            this.instanceUrl = instanceUrl;
            this.signature = signature;
        }

        public String getId()
        {
            return id;
        }

        public String getScope()
        {
            return scope;
        }

        public Date getIssuedAt()
        {
            return issuedAt;
        }

        public String getInstanceUrl()
        {
            return instanceUrl;
        }

        public String getSignature()
        {
            return signature;
        }
    }

}
