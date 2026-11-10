# 🧪 PrivacyGuard Synthetic Demonstration Data

> [!IMPORTANT]
> **Strict Isolation Notice:** All files in this directory are purely **synthetic evaluation targets** designed for hackathon demonstrations, automated testing, and explainability verification. They do not contain real user personal data, proprietary enterprise information, or live credentials.

---

## 📂 Included Synthetic Scenarios

| Application Target | Purpose & Category | Manifest File | Policy Excerpt | Key Explainability Characteristics |
| :--- | :--- | :--- | :--- | :--- |
| **QuickScan Document Manager** | Productivity / Document Scanning | [`sample_manifest.xml`](sample_manifest.xml) | [`sample_privacy_policy.txt`](sample_privacy_policy.txt) | Demonstrates standard dangerous permissions (`CAMERA`), install-time network permissions, and uncataloged vendor permissions (`com.synthetic.vendor.custom.DIAGNOSTIC_TELEMETRY`) triggering strict `UNKNOWN` explainability. |
| **Synthetic Minimal Calculator** | Utility / Arithmetic | [`calculator/synthetic_calculator_manifest.xml`](calculator/synthetic_calculator_manifest.xml) | [`calculator/synthetic_calculator_policy.txt`](calculator/synthetic_calculator_policy.txt) | Low-risk profile requesting only `VIBRATE` (haptic button feedback) and `INTERNET` for banner ads, fully verified against declared policy. |
| **RoadMaster Navigation** | Travel & Maps | [`navigation/synthetic_navigation_manifest.xml`](navigation/synthetic_navigation_manifest.xml) | [`navigation/synthetic_navigation_policy.txt`](navigation/synthetic_navigation_policy.txt) | Location-heavy profile with `ACCESS_FINE_LOCATION`, `ACCESS_BACKGROUND_LOCATION`, and `FOREGROUND_SERVICE`, showing purpose-alignment explanations. |
| **Pulse Chat & Messaging** | Communication / Social | [`messaging/synthetic_messaging_manifest.xml`](messaging/synthetic_messaging_manifest.xml) | [`messaging/synthetic_messaging_policy.txt`](messaging/synthetic_messaging_policy.txt) | Demonstrates multi-permission attack chains (Camera + Microphone + Contacts) and privacy policy grounding. |

---

## 🎯 Verification and Usage in Hackathon Flow

1. **Direct File Upload Demonstration:**
   - In the **New Analysis** wizard (Upload tab), drag and drop [`sample_manifest.xml`](sample_manifest.xml).
   - Enter application purpose: `"Scan receipts and documents using the camera"`.
   - Paste text from [`sample_privacy_policy.txt`](sample_privacy_policy.txt).
   - Click **Run Audit Analysis**.
2. **One-Click Preloaded Benchmarks:**
   - Evaluators can also navigate to the **Pre-Loaded Benchmarks** tab in the wizard to test Calculator, Navigation, or Messaging targets instantly with pre-populated synthetic inputs.

