package es.chiteroman.bootloaderspoofer;

import com.google.common.primitives.Bytes;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;

import java.security.KeyStore;
import java.security.KeyStoreSpi;
import java.security.cert.Certificate;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import de.robv.android.xposed.callbacks.XCallback;

public class Xposed implements IXposedHookLoadPackage {
    private static final HOOK hook = new HOOK();

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            KeyStoreSpi keyStoreSpi = (KeyStoreSpi) XposedHelpers.getObjectField(keyStore, "keyStoreSpi");
            XposedHelpers.findAndHookMethod(keyStoreSpi.getClass(), "engineGetCertificateChain", String.class, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Certificate[] certificates = (Certificate[]) param.getResultOrThrowable();
                    for (Certificate certificate : certificates) {
                        XposedHelpers.findAndHookMethod(certificate.getClass(), "getExtensionValue", String.class, hook);
                    }
                }
            });
        } catch (Throwable t) {
            XposedBridge.log(t);
        }
    }

    private static final class HOOK extends XC_MethodHook {
        public HOOK() {
            super(XCallback.PRIORITY_HIGHEST);
        }

        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            byte[] bytes = (byte[]) param.getResultOrThrowable();
            String oid = (String) param.args[0];

            if (oid == null || bytes == null) return;

            if (!oid.equalsIgnoreCase("1.3.6.1.4.1.11129.2.1.17")) return;

            ASN1Sequence asn1Sequence;
            try (ASN1InputStream asn1InputStream = new ASN1InputStream(bytes)) {
                ASN1OctetString asn1OctetString = (ASN1OctetString) asn1InputStream.readObject();
                try (ASN1InputStream asn1InputStream1 = new ASN1InputStream(asn1OctetString.getOctets())) {
                    asn1Sequence = (ASN1Sequence) asn1InputStream1.readObject();
                }
            }
            if (asn1Sequence == null) return;

            ASN1Sequence teeEnforced = (ASN1Sequence) asn1Sequence.getObjectAt(7);

            ASN1Sequence rootOfTrust = null;
            for (ASN1Encodable encodable : teeEnforced) {
                ASN1TaggedObject asn1TaggedObject = (ASN1TaggedObject) encodable;
                if (asn1TaggedObject.getTagNo() == 704) {
                    rootOfTrust = (ASN1Sequence) asn1TaggedObject.getBaseObject();
                    break;
                }
            }
            if (rootOfTrust == null) return;

            byte[] rootOfTrustBytes = rootOfTrust.getEncoded();
            int rootOfTrustIndex = Bytes.indexOf(bytes, rootOfTrustBytes);

            ASN1Boolean deviceLocked = (ASN1Boolean) rootOfTrust.getObjectAt(1);
            ASN1Enumerated verifiedBootState = (ASN1Enumerated) rootOfTrust.getObjectAt(2);

            int deviceLockedIndex = Bytes.indexOf(rootOfTrustBytes, deviceLocked.getEncoded());
            int verifiedBootStateIndex = Bytes.indexOf(rootOfTrustBytes, verifiedBootState.getEncoded());

            int patchDeviceLockedIndex = rootOfTrustIndex + deviceLockedIndex + 2;
            int patchVerifiedBootStateIndex = rootOfTrustIndex + verifiedBootStateIndex + 2;

            bytes[patchDeviceLockedIndex] = 1;
            bytes[patchVerifiedBootStateIndex] = 0;

            param.setResult(bytes);
        }
    }
}
