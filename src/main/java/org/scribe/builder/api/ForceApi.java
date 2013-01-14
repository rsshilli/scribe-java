/**
 * The MIT License
 *
 * Copyright (c) 2011, salesforce.com, inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
// This was modified.  Original is at: https://github.com/tkral/scribe-java/blob/996ae023f4b71a30bfe94c38f4e98fbdde2ccd35/src/main/java/org/scribe/builder/api/ForceDotComApi.java
package org.scribe.builder.api;


import org.scribe.extractors.AccessTokenExtractor;
import org.scribe.extractors.ForceTokenExtractor;
import org.scribe.model.OAuthConfig;
import org.scribe.model.OAuthConstants;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.oauth.OAuth20ServiceImpl;
import org.scribe.oauth.OAuthService;
import org.scribe.utils.OAuthEncoder;
import org.scribe.utils.Preconditions;

/**
 * This is to use the Force.com (or SalesForce.com) OAuth APIs.
 * <p/>
 * This class uses the production instance, which is the default.  If you want the Sandbox or PreRelease instance, use ForceAPI.Sandbox.class or
 * ForceAPI.PreRelease.class respectively.
 *
 * @author Tim Kral, Ryan Shillington
 */
public class ForceApi extends DefaultApi20
{

    private static final String AUTHORIZE_URL_PATH = "/services/oauth2/authorize?response_type=code&client_id=%s&redirect_uri=%s";
    private static final String SCOPED_AUTHORIZE_URL_PATH = AUTHORIZE_URL_PATH + "&scope=%s";
    private static final String ACCESS_URL_PATH = "/services/oauth2/token?grant_type=authorization_code";

    protected String baseURL = "https://login.salesforce.com";

    public static class Sandbox extends ForceApi
    {
        public Sandbox()
        {
            baseURL = "https://test.salesforce.com";
        }
    }

    public static class PreRelease extends ForceApi
    {
        public PreRelease()
        {
            baseURL = "https://prerellogin.pre.salesforce.com";
        }
    }

    public ForceApi() { }

    @Override
    public String getAccessTokenEndpoint()
    {
        return baseURL + ACCESS_URL_PATH;
    }

    @Override
    public AccessTokenExtractor getAccessTokenExtractor()
    {
        return new ForceTokenExtractor();
    }

    @Override
    public Verb getAccessTokenVerb()
    {
        return Verb.POST;
    }

    @Override
    public String getAuthorizationUrl(OAuthConfig config)
    {
        Preconditions.checkValidUrl(config.getCallback(), "Must provide a valid url as callback. Force.com does not support OOB");

        if (config.hasScope())
        {
            return String.format(baseURL + SCOPED_AUTHORIZE_URL_PATH, config.getApiKey(), OAuthEncoder.encode(config.getCallback()),
                    OAuthEncoder.encode(config.getScope()));
        } else
        {
            return String.format(baseURL + AUTHORIZE_URL_PATH, config.getApiKey(), OAuthEncoder.encode(config.getCallback()));
        }
    }

    @Override
    public OAuthService createService(OAuthConfig config)
    {
        return new OAuth20ServiceImpl(this, config)
        {
            @Override
            /**
             * This signs requests in the header where the Force.com * OAuth service expects to find it.
             */
            public void signRequest(Token accessToken, OAuthRequest request)
            {
                request.addHeader(OAuthConstants.HEADER, "Bearer " + accessToken.getToken());
            }
        };
    }
}
