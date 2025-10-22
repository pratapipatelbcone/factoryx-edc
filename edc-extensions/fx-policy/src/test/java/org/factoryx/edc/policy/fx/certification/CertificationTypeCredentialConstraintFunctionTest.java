/********************************************************************************
 * Copyright (c) 2025 SAP SE
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License, Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

package org.factoryx.edc.policy.fx.certification;

import org.eclipse.edc.participant.spi.ParticipantAgent;
import org.eclipse.edc.participant.spi.ParticipantAgentPolicyContext;
import org.eclipse.edc.policy.model.Operator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.factoryx.edc.edr.spi.CoreConstants.FX_POLICY_NS;
import static org.factoryx.edc.policy.fx.CredentialFunctions.createCertificateTypeCredential;
import static org.factoryx.edc.policy.fx.CredentialFunctions.createCredential;
import static org.factoryx.edc.policy.fx.certification.CertificationTypeCredentialConstraintFunction.CERTIFICATION_LITERAL;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CertificationTypeCredentialConstraintFunctionTest {

    public static final String A_CERTIFICATE_TYPE = "ACertificateType";

    private final ParticipantAgentPolicyContext context = mock();
    private final ParticipantAgent participantAgent = mock();

    private final CertificationTypeCredentialConstraintFunction<ParticipantAgentPolicyContext> function = new CertificationTypeCredentialConstraintFunction<>();

    @BeforeEach
    void setup() {
        when(context.participantAgent()).thenReturn(participantAgent);
    }

    @Test
    void evaluate_invalidOperator() {
        when(context.participantAgent()).thenReturn(null);
        assertThat(function.evaluate(FX_POLICY_NS + CERTIFICATION_LITERAL, Operator.IS_NONE_OF, A_CERTIFICATE_TYPE, null, context)).isFalse();
    }

    @Test
    void evaluate_invalidRightOperandType() {
        when(context.participantAgent()).thenReturn(null);
        assertThat(function.evaluate(FX_POLICY_NS + CERTIFICATION_LITERAL, Operator.EQ, List.of("InvalidRightOperandType"), null, context)).isFalse();
    }

    @Test
    void evaluate_noParticipantAgentOnContext() {
        when(context.participantAgent()).thenReturn(null);
        assertThat(function.evaluate(FX_POLICY_NS + CERTIFICATION_LITERAL, Operator.EQ, A_CERTIFICATE_TYPE, null, context)).isFalse();
        verify(context).reportProblem("Required PolicyContext data not found: org.eclipse.edc.participant.spi.ParticipantAgent");
    }

    @Test
    void evaluate_noVcClaimOnParticipantAgent() {
        assertThat(function.evaluate(FX_POLICY_NS + CERTIFICATION_LITERAL, Operator.EQ, A_CERTIFICATE_TYPE, null, context)).isFalse();
        verify(context).reportProblem(eq("ParticipantAgent did not contain a 'vc' claim."));
    }

    @Test
    void evaluate_vcClaimEmpty() {
        when(participantAgent.getClaims()).thenReturn(Map.of("vc", List.of()));
        assertThat(function.evaluate(FX_POLICY_NS + CERTIFICATION_LITERAL, Operator.EQ, A_CERTIFICATE_TYPE, null, context)).isFalse();
        verify(context).reportProblem(eq("ParticipantAgent contains a 'vc' claim but it did not contain any VerifiableCredentials."));
    }

    @Test
    void evaluate_vcClaimNotList() {
        when(participantAgent.getClaims()).thenReturn(Map.of("vc", new Object()));
        assertThat(function.evaluate(FX_POLICY_NS + CERTIFICATION_LITERAL, Operator.EQ, A_CERTIFICATE_TYPE, null, context)).isFalse();
        verify(context).reportProblem(eq("ParticipantAgent contains a 'vc' claim, but the type is incorrect. Expected java.util.List, received java.lang.Object."));
    }

    @Test
    void evaluate_rightOperandNotMatchesCertificateTypeClaim() {
        when(participantAgent.getClaims()).thenReturn(Map.of("vc", List.of(createCertificateTypeCredential(A_CERTIFICATE_TYPE).build())));
        assertThat(function.evaluate(FX_POLICY_NS + CERTIFICATION_LITERAL, Operator.EQ, "invalid", null, context)).isFalse();
    }

    @Test
    void evaluate_whenSingleCredentialFound() {
        when(participantAgent.getClaims()).thenReturn(Map.of("vc", List.of(createCertificateTypeCredential(A_CERTIFICATE_TYPE).build())));
        assertThat(function.evaluate(FX_POLICY_NS + CERTIFICATION_LITERAL, Operator.EQ, A_CERTIFICATE_TYPE, null, context)).isTrue();
    }

    @Test
    void evaluate_whenMultipleCredentialsFound() {
        when(participantAgent.getClaims()).thenReturn(Map.of("vc", List.of(createCertificateTypeCredential(A_CERTIFICATE_TYPE).build(),
                createCertificateTypeCredential(A_CERTIFICATE_TYPE).build(),
                createCredential("BogusCredential").build())));
        assertThat(function.evaluate(FX_POLICY_NS + CERTIFICATION_LITERAL, Operator.EQ, A_CERTIFICATE_TYPE, null, context)).isTrue();

    }

    @Test
    void evaluate_whenCredentialNotFound() {
        when(participantAgent.getClaims()).thenReturn(Map.of("vc", List.of(createCredential("BogusCredential").build())));
        assertThat(function.evaluate(FX_POLICY_NS + CERTIFICATION_LITERAL, Operator.EQ, A_CERTIFICATE_TYPE, null, context)).isFalse();
    }


    @Test
    void test_CanHandle() {

        // invalid left operand type
        assertThat(function.canHandle(List.of())).isFalse();

        // invalid literal
        assertThat(function.canHandle("AnyLiteral")).isFalse();

        // valid literal without namespace
        assertThat(function.canHandle(CERTIFICATION_LITERAL)).isFalse();

        //  valid literal with namespace
        assertThat(function.canHandle(FX_POLICY_NS + CERTIFICATION_LITERAL)).isTrue();
    }
}
