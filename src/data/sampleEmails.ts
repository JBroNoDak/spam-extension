import { EmailMessage } from '../types';

export const SAMPLE_EMAILS: EmailMessage[] = [
  {
    id: 'msg-1',
    sender: {
      name: 'Google Workspace Security Team',
      email: 'security-alert@support-googIe.com',
      domain: 'support-googIe.com',
      isExternal: true,
    },
    recipient: 'employee@acmecorp.com',
    date: '10:42 AM (18 minutes ago)',
    subject: 'CRITICAL ALERT: Unauthorized Access Attempt Detected - Verify Account Immediately',
    snippet: 'We noticed unusual sign-in activity from an unrecognized device in Nizhny Novgorod, Russia. Your workspace access will be suspended in 2 hours...',
    isExternal: true,
    headers: {
      spf: 'fail',
      dkim: 'fail',
      dmarc: 'fail',
      returnPath: 'bounce-daemon@support-googIe.com',
      ipAddress: '185.220.101.54',
      deliveredTo: 'employee@acmecorp.com',
    },
    tags: ['Urgent', 'External', 'Security'],
    attachments: [
      {
        id: 'att-1',
        filename: 'SecurityVerification_Report.pdf.exe',
        size: '1.4 MB',
        type: 'application/x-msdownload',
      },
      {
        id: 'att-2',
        filename: 'Activity_Log_Snapshot.png',
        size: '240 KB',
        type: 'image/png',
      },
    ],
    bodyText: `Dear Workspace User,

We noticed a suspicious sign-in attempt to your organization account from an unrecognized IP address (185.220.101.54 - Nizhny Novgorod, Russian Federation).

If this was not you, your organization security policies mandate immediate credential synchronization. Failure to re-authenticate within 2 hours will lead to permanent workspace account suspension and email revocation.

Please review your sign-in activity and verify your identity below:
👉 Click to Verify Google Workspace Account: https://accounts.google.com/signin/v2/challenge

Alternatively, execute the attached diagnostic tool to confirm machine integrity.

Google Cloud Security Operations
Mountain View, CA`,
    bodyHtml: `
      <div style="font-family: Arial, sans-serif; color: #202124; line-height: 1.6;">
        <div style="padding-bottom: 12px; border-bottom: 1px solid #e0e0e0; margin-bottom: 16px;">
          <h3 style="color: #d93025; margin: 0 0 4px 0;">Action Required: High-Severity Security Alert</h3>
          <p style="margin: 0; color: #5f6368; font-size: 13px;">Google Workspace Identity Protection Service</p>
        </div>
        
        <p>Dear Workspace User,</p>
        
        <p>We detected an unauthorized sign-in attempt targeting your enterprise account from an unknown device in <strong>Nizhny Novgorod, Russia</strong> (IP: <code>185.220.101.54</code>).</p>
        
        <div style="background: #fce8e6; border-left: 4px solid #d93025; padding: 12px; margin: 16px 0; border-radius: 4px;">
          <strong style="color: #c5221f;">Immediate Action Required:</strong> To prevent data exfiltration, your administrator session will terminate within <strong>2 hours</strong> unless ownership is confirmed.
        </div>
        
        <p>Click below to verify your identity and keep your corporate mail active:</p>
        
        <p style="margin: 24px 0;">
          <a href="http://accounts-googIe.com/login/challenge?ref=acmecorp" target="_blank" style="background-color: #1a73e8; color: #ffffff; padding: 10px 20px; text-decoration: none; border-radius: 4px; font-weight: 500; display: inline-block;">
            Verify Workspace Credentials Now
          </a>
        </p>

        <p style="font-size: 13px; color: #5f6368;">
          Or review direct URL: <a href="http://185.220.101.54/auth/recovery" target="_blank">https://accounts.google.com/security/recovery</a>
        </p>
        
        <p style="font-size: 12px; color: #70757a; margin-top: 30px; border-top: 1px solid #eee; padding-top: 12px;">
          Google LLC, 1600 Amphitheatre Parkway, Mountain View, CA 94043. This is a mandatory external notification.
        </p>
      </div>
    `,
  },
  {
    id: 'msg-2',
    sender: {
      name: 'Richard Harris (CEO)',
      email: 'ceo.richard.harris.acme@gmail.com',
      domain: 'gmail.com',
      isExternal: true,
    },
    recipient: 'finance-team@acmecorp.com',
    date: '9:15 AM (1.5 hours ago)',
    subject: 'URGENT: Confidential Supplier Wire - Process before 11:30 AM EST',
    snippet: 'I am tied up in an off-site executive board meeting with our private equity partners. Need an expedited international wire transfer processed ASAP...',
    isExternal: true,
    headers: {
      spf: 'pass',
      dkim: 'pass',
      dmarc: 'fail',
      returnPath: 'ceo.richard.harris.acme@gmail.com',
      ipAddress: '209.85.220.41',
      deliveredTo: 'finance-team@acmecorp.com',
    },
    tags: ['Finance', 'External', 'Urgent'],
    attachments: [
      {
        id: 'att-3',
        filename: 'Wire_Instruction_M&A_Confidential.zip',
        size: '850 KB',
        type: 'application/zip',
      },
    ],
    bodyText: `Good morning,

I am currently in an off-site confidential acquisition meeting with the board and cannot take phone calls. 

We need to close the first tranche of the European infrastructure acquisition today before the London clearing house closes at 11:30 AM EST. 

Please find the wire payment instructions attached in the confidential zip file. Transfer $84,500 USD to the beneficiary bank provided. 

Confirm once queued so I can update legal. Do not mention this to anyone on the floor until the public press release tomorrow morning.

Sent from my iPhone
Richard Harris
Chief Executive Officer`,
    bodyHtml: `
      <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #111827; line-height: 1.5;">
        <p>Good morning,</p>
        <p>I am currently tied up in an off-site confidential acquisition meeting with our board and investment committee. My phone line is muted.</p>
        <p>We need to finalize the escrow deposit for the overseas supplier contract before <strong>11:30 AM EST</strong> today.</p>
        <p>Attached are the updated SWIFT coordinates and invoice schedule: 
           <a href="http://bit.ly/3xSecAcmeWire" target="_blank">Download Beneficiary Verification Sheet</a>
        </p>
        <p>Please initiate the wire transfer of <strong>$84,500.00 USD</strong> immediately. Confirm back to this personal email as my corporate inbox is currently inaccessible on this tablet.</p>
        <br/>
        <p style="color: #4b5563; font-style: italic;">
          Sent from my iPad<br>
          <strong>Richard Harris</strong><br>
          Chief Executive Officer | Acme Global Holdings
        </p>
      </div>
    `,
  },
  {
    id: 'msg-3',
    sender: {
      name: 'DocuSign Electronic Signature',
      email: 'notifications@docus1gn-signnow.com',
      domain: 'docus1gn-signnow.com',
      isExternal: true,
    },
    recipient: 'employee@acmecorp.com',
    date: 'Yesterday, 4:20 PM',
    subject: 'Please DocuSign: Q3 Non-Disclosure & Compensation Adjustment Agreement.pdf',
    snippet: 'Human Resources sent you a document for electronic signature. Please review and sign within 24 hours to ensure continuous payroll eligibility...',
    isExternal: true,
    headers: {
      spf: 'neutral',
      dkim: 'none',
      dmarc: 'none',
      returnPath: 'bounces@docus1gn-signnow.com',
      ipAddress: '45.142.214.99',
      deliveredTo: 'employee@acmecorp.com',
    },
    tags: ['DocuSign', 'External', 'HR'],
    attachments: [],
    bodyText: `DocuSign Document Notification:

Your HR Compensation Committee has issued an updated Q3 Employee Equity & Retention Agreement for your electronic signature.

DOCUMENT DETAILS:
Document Name: Q3_Compensation_Adjustment_Final.pdf
Security Level: Restricted / Internal Use Only
Sign Deadline: 24 Hours

Click here to view and sign your document:
https://docusign.com/sign/v84920492?auth=user

Thank you for choosing DocuSign.`,
    bodyHtml: `
      <div style="font-family: Arial, sans-serif; color: #333; max-width: 580px; margin: 0 auto; border: 1px solid #dcdcdc; border-radius: 6px; overflow: hidden;">
        <div style="background-color: #2e358b; padding: 18px 24px; color: white;">
          <h2 style="margin: 0; font-size: 20px; font-weight: 600;">DocuSign Electronic Signature Service</h2>
        </div>
        <div style="padding: 24px;">
          <p style="font-size: 15px; margin-top: 0;"><strong>Human Resources Dept</strong> sent you a confidential document to review and complete.</p>
          <div style="background-color: #f7f9fa; border: 1px solid #e1e4e6; border-radius: 4px; padding: 16px; margin: 20px 0;">
            <p style="margin: 0 0 6px 0; font-weight: bold; color: #1e1e1e;">Q3_Compensation_Adjustment_Agreement.pdf</p>
            <p style="margin: 0; font-size: 13px; color: #666;">Expires in 24 hours • Total 4 pages</p>
          </div>
          <div style="text-align: center; margin: 30px 0;">
            <a href="http://docus1gn-signnow.com/portal/sign-in.php" target="_blank" style="background-color: #ffc820; color: #1e1e1e; font-weight: bold; text-decoration: none; padding: 12px 36px; border-radius: 3px; font-size: 15px; display: inline-block;">
              REVIEW DOCUMENT
            </a>
          </div>
          <p style="font-size: 12px; color: #777;">
            Alternate direct sign portal: <a href="http://194.26.29.112/docusign/login.html" target="_blank">https://na3.docusign.net/Member/PowerFormSigning.aspx</a>
          </p>
        </div>
      </div>
    `,
  },
  {
    id: 'msg-4',
    sender: {
      name: 'Global Freight & Logistics Billing',
      email: 'billing@freight-express-logistics.net',
      domain: 'freight-express-logistics.net',
      isExternal: true,
    },
    recipient: 'operations@acmecorp.com',
    date: 'Yesterday, 11:05 AM',
    subject: 'Overdue Delivery Invoice INV-98402 & Customs Clearance Slip',
    snippet: 'Your commercial consignment is pending customs release at port of entry. Please inspect the attached macro-enabled manifest to authorize duty discharge...',
    isExternal: true,
    headers: {
      spf: 'pass',
      dkim: 'pass',
      dmarc: 'pass',
      returnPath: 'mailer@freight-express-logistics.net',
      ipAddress: '198.51.100.12',
      deliveredTo: 'operations@acmecorp.com',
    },
    tags: ['Logistics', 'External', 'Billing'],
    attachments: [
      {
        id: 'att-4',
        filename: 'Customs_Release_INV98402.docm',
        size: '340 KB',
        type: 'application/vnd.ms-word.document.macroEnabled.12',
      },
      {
        id: 'att-5',
        filename: 'Waybill_Manifest_Scan.pdf',
        size: '1.1 MB',
        type: 'application/pdf',
      },
    ],
    bodyText: `Attention Logistics Manager,

Your scheduled sea-freight shipment container #MSC78401 is held up at port customs awaiting clearance authorization.

Attached is the customs clearance declaration file (Customs_Release_INV98402.docm). Please open the document in Microsoft Word and enable active content/macros to generate the customs signature token.

You can also download the tracking manifest directly: http://freight-express-logistics.net/downloads/manifest.docm

Regards,
Global Port Clearance Operations`,
    bodyHtml: `
      <div style="font-family: Arial, sans-serif; color: #333; line-height: 1.5;">
        <h3 style="color: #0d47a1;">Customs Clearance Notice - Overdue Container Fee</h3>
        <p>Dear Operations Team,</p>
        <p>Container shipment <strong>#MSC78401</strong> from Hamburg is currently impounded at the Port Authority.</p>
        <p>To avoid escalating demurrage charges ($350/day), please review the attached document <code>Customs_Release_INV98402.docm</code>.</p>
        <div style="background: #fff3e0; border: 1px solid #ffe0b2; padding: 12px; border-radius: 4px; margin: 16px 0;">
          <strong>Instructions:</strong> Open the attachment in Microsoft Word and select <em>"Enable Editing"</em> followed by <em>"Enable Content/Macros"</em> to auto-calculate duty fees.
        </div>
        <p>Direct mirror download: <a href="http://insecure-cdn-storage.org/files/Customs_Release_INV98402.docm" target="_blank">http://freight-express-logistics.net/files/customs-declaration</a></p>
      </div>
    `,
  },
  {
    id: 'msg-5',
    sender: {
      name: 'Slack Enterprise Notifications',
      email: 'feedback@slack.com',
      domain: 'slack.com',
      isExternal: true,
    },
    recipient: 'employee@acmecorp.com',
    date: 'Sep 8, 2026',
    subject: 'New feature announcement: Canvas AI summarize in Slack channels',
    snippet: 'We have updated Slack Canvas with automatic meeting summary recaps and thread integration. Explore how your team can collaborate faster...',
    isExternal: true,
    headers: {
      spf: 'pass',
      dkim: 'pass',
      dmarc: 'pass',
      returnPath: 'bounces@feedback.slack.com',
      ipAddress: '54.240.14.88',
      deliveredTo: 'employee@acmecorp.com',
    },
    tags: ['Productivity', 'External', 'Verified'],
    attachments: [
      {
        id: 'att-6',
        filename: 'Slack_Canvas_UserGuide_2026.pdf',
        size: '2.3 MB',
        type: 'application/pdf',
      },
    ],
    bodyText: `Hello team,

We are excited to roll out new generative summaries for Slack Canvas across all Enterprise Grid workspaces.

Take a look at the product update and video overview here:
https://slack.com/blog/productivity/introducing-slack-canvas-ai

You can also review the attached documentation PDF.

Best regards,
The Slack Team`,
    bodyHtml: `
      <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #1d1c1d; line-height: 1.5; max-width: 600px;">
        <h2 style="color: #4a154b; margin-top: 0;">Introducing Canvas AI for Slack</h2>
        <p>Hi there,</p>
        <p>Starting this week, enterprise teams can organize brainstorming sessions, sprint notes, and meeting agendas directly inside Slack channels.</p>
        <p>Learn more about how to enable Canvas in your workspace settings:</p>
        <p style="margin: 20px 0;">
          <a href="https://slack.com/help/articles/canvas-collaboration" target="_blank" style="background-color: #007a5a; color: white; padding: 10px 18px; text-decoration: none; border-radius: 4px; font-weight: bold; display: inline-block;">
            Read the Feature Guide
          </a>
        </p>
        <p style="font-size: 13px; color: #616061;">
          View our release notes at <a href="https://slack.com/release-notes" target="_blank">https://slack.com/release-notes</a>
        </p>
      </div>
    `,
  },
  {
    id: 'msg-6',
    sender: {
      name: 'Sarah Jenkins (Engineering)',
      email: 's.jenkins@acmecorp.com',
      domain: 'acmecorp.com',
      isExternal: false,
    },
    recipient: 'employee@acmecorp.com',
    date: 'Sep 7, 2026',
    subject: 'Internal Sprint Planning & Architecture Review - Thursday 2 PM',
    snippet: 'Hey team, here is the agenda for our upcoming sprint refinement. Please review the internal engineering tickets in Jira before our standup...',
    isExternal: false,
    headers: {
      spf: 'pass',
      dkim: 'pass',
      dmarc: 'pass',
      returnPath: 's.jenkins@acmecorp.com',
      ipAddress: '10.0.4.12',
      deliveredTo: 'employee@acmecorp.com',
    },
    tags: ['Internal', 'Engineering'],
    attachments: [
      {
        id: 'att-7',
        filename: 'Architecture_Diagram_V4.png',
        size: '1.8 MB',
        type: 'image/png',
      },
    ],
    bodyText: `Hey everyone,

Quick reminder about Thursday's architecture review. We will walk through the microservices decoupling roadmap and discuss the caching tier.

Jira epic: https://jira.internal.acmecorp.com/browse/ENG-4021
Meeting notes: https://docs.google.com/document/d/14892040

Let me know if you want to add any talking points to the slide deck.

Thanks,
Sarah`,
    bodyHtml: `
      <div style="font-family: Arial, sans-serif; color: #222; line-height: 1.5;">
        <p>Hey everyone,</p>
        <p>Quick reminder about Thursday's architecture sync at 2 PM PST.</p>
        <p>Please review our Jira epic before joining: <a href="https://jira.internal.acmecorp.com/browse/ENG-4021" target="_blank">ENG-4021: Microservices Decoupling</a></p>
        <p>Architecture diagram is attached. See you all then!</p>
        <p>Cheers,<br>Sarah Jenkins<br><span style="color: #666; font-size: 12px;">Staff Software Engineer | Acme Corp</span></p>
      </div>
    `,
  },
];
