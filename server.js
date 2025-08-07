const express = require("express");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const ExcelJS = require("exceljs");
require("dotenv").config();

const { S3Client, PutObjectCommand } = require("@aws-sdk/client-s3");
const { DynamoDBClient } = require("@aws-sdk/client-dynamodb");
const {
  DynamoDBDocumentClient,
  PutCommand,
  ScanCommand,
} = require("@aws-sdk/lib-dynamodb");

const app = express();
const PORT = process.env.PORT || 5002;

// =================== AWS CREDENTIALS DEBUG & VALIDATION ===================
console.log("🔍 Environment Variables Debug:");
console.log(
  "AWS_ACCESS_KEY_ID:",
  process.env.AWS_ACCESS_KEY_ID ? "✅ Present" : "❌ Missing"
);
console.log(
  "AWS_SECRET_ACCESS_KEY:",
  process.env.AWS_SECRET_ACCESS_KEY ? "✅ Present" : "❌ Missing"
);
console.log("AWS_REGION:", process.env.AWS_REGION || "❌ Missing");
console.log("AWS_S3_BUCKET:", process.env.AWS_S3_BUCKET || "❌ Missing");

// Show first few characters for verification (don't log full credentials)
if (process.env.AWS_ACCESS_KEY_ID) {
  console.log(
    "Access Key starts with:",
    process.env.AWS_ACCESS_KEY_ID.substring(0, 4) + "..."
  );
}
if (process.env.AWS_SECRET_ACCESS_KEY) {
  console.log("Secret Key length:", process.env.AWS_SECRET_ACCESS_KEY.length);
}

// Validate AWS credentials before proceeding
const validateAWSCredentials = () => {
  const requiredVars = [
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_REGION",
    "AWS_S3_BUCKET",
  ];
  const missing = requiredVars.filter((varName) => !process.env[varName]);

  if (missing.length > 0) {
    console.error("❌ Missing AWS environment variables:", missing);
    console.error(
      "Please check your .env file and ensure all AWS credentials are set"
    );
    console.error("Required format in .env:");
    console.error("AWS_ACCESS_KEY_ID=your_access_key");
    console.error("AWS_SECRET_ACCESS_KEY=your_secret_key");
    console.error("AWS_REGION=ap-south-1");
    console.error("AWS_S3_BUCKET=your_bucket_name");
    process.exit(1);
  }

  console.log("✅ All AWS environment variables are present");
};

// Call validation before creating AWS clients
validateAWSCredentials();

// Middleware - Updated CORS to allow both frontend origins
app.use(cors({ 
  origin: ["http://localhost:3000", "http://localhost:3001"],
  credentials: true 
}));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// AWS Configuration (after validation)
const REGION = process.env.AWS_REGION;
const s3 = new S3Client({
  region: REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});

const dynamoClient = new DynamoDBClient({
  region: REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});
const dynamodb = DynamoDBDocumentClient.from(dynamoClient);

// Enhanced AWS operation wrapper
const handleAWSOperation = async (operation, operationName) => {
  try {
    return await operation();
  } catch (error) {
    if (error.message.includes("Resolved credential object is not valid")) {
      console.error(`❌ AWS Credential Error in ${operationName}:`, {
        message: error.message,
        accessKeyId: process.env.AWS_ACCESS_KEY_ID ? "Present" : "Missing",
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
          ? "Present"
          : "Missing",
        region: process.env.AWS_REGION || "Missing",
      });
      throw new Error(
        `AWS credentials are invalid. Please check your .env file.`
      );
    }
    throw error;
  }
};

// Multer setup for file uploads (from student submission service)
const upload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (req, file, cb) => {
    console.log(`Received file: ${file.fieldname} - ${file.originalname}`);

    const allowedFields = [
      "categoryCert",
      "feeReceipt",
      "appForm",
      "jeeScorecard",
      "marksheet12",
      "allotmentLetter",
      "pwdCert",
    ];

    if (allowedFields.includes(file.fieldname)) {
      cb(null, true);
    } else {
      console.error(`Unexpected file field: ${file.fieldname}`);
      cb(new Error(`Unexpected file field: ${file.fieldname}`), false);
    }
  },
});

const cpUpload = upload.fields([
  { name: "categoryCert", maxCount: 1 },
  { name: "feeReceipt", maxCount: 1 },
  { name: "appForm", maxCount: 1 },
  { name: "jeeScorecard", maxCount: 1 },
  { name: "marksheet12", maxCount: 1 },
  { name: "allotmentLetter", maxCount: 1 },
  { name: "pwdCert", maxCount: 1 },
]);

// Enhanced S3 upload helper with error handling
const uploadToS3 = async (buffer, fileName, mimeType) => {
  const bucketName = process.env.AWS_S3_BUCKET;
  const key = `admissions/${fileName}`;

  const command = new PutObjectCommand({
    Bucket: bucketName,
    Key: key,
    Body: buffer,
    ContentType: mimeType,
  });

  // Use enhanced AWS operation wrapper
  await handleAWSOperation(() => s3.send(command), "S3 Upload");
  return `https://${bucketName}.s3.${REGION}.amazonaws.com/${key}`;
};

// Admin credentials and JWT setup (from admin service)
const ADMIN_CREDENTIALS = {
  username: "admin",
  password: "admin123",
};

const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key-for-development";

// Authentication middleware for admin routes
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access token required" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Invalid or expired token" });
    }
    req.user = user;
    next();
  });
};

// =================== ROUTES ===================

// Root endpoint
app.get("/", (req, res) => {
  res.send("GGU Unified Admission Backend is running.");
});

// =================== STUDENT SUBMISSION ROUTES ===================

app.post(
  "/api/admission",
  (req, res, next) => {
    console.log("\n=== New Form Submission ===");
    cpUpload(req, res, (err) => {
      if (err) {
        console.error("Multer Error:", err.message);
        if (err instanceof multer.MulterError) {
          return res.status(400).json({
            success: false,
            error: `File upload error: ${err.message}`,
            code: err.code,
          });
        }
        return res.status(400).json({
          success: false,
          error: err.message,
        });
      }
      next();
    });
  },
  async (req, res) => {
    try {
      const fields = req.body;
      const files = req.files;

      console.log("Form fields received:", Object.keys(fields));
      console.log("Files received:", Object.keys(files || {}));

      const formData = {
        ...fields,
        student_email: fields.email?.toLowerCase(),
        student_name: fields.name,
        submission_date: new Date().toISOString(),
        submission_id: `admission_${Date.now()}`,
      };

      // Upload files to S3 with enhanced error handling
      const fileUploadPromises = [];
      const fileFields = [
        "categoryCert",
        "feeReceipt",
        "appForm",
        "jeeScorecard",
        "marksheet12",
        "allotmentLetter",
        "pwdCert",
      ];

      for (const field of fileFields) {
        if (files[field]) {
          const file = files[field][0];
          const filename = `${field}-${Date.now()}${path.extname(
            file.originalname
          )}`;
          fileUploadPromises.push(
            uploadToS3(file.buffer, filename, file.mimetype).then((url) => {
              formData[field] = url;
            })
          );
        }
      }

      // Wait for all file uploads to complete
      await Promise.all(fileUploadPromises);

      // Save to DynamoDB with enhanced error handling
      await handleAWSOperation(
        () =>
          dynamodb.send(
            new PutCommand({
              TableName: "Student",
              Item: formData,
            })
          ),
        "DynamoDB Save"
      );

      console.log("✅ Form submission successful");

      res.status(200).json({
        success: true,
        message: "Application submitted successfully",
        submissionId: formData.submission_id,
        fileUrls: {
          categoryCert: formData.categoryCert || null,
          feeReceipt: formData.feeReceipt || null,
          appForm: formData.appForm || null,
          jeeScorecard: formData.jeeScorecard || null,
          marksheet12: formData.marksheet12 || null,
          allotmentLetter: formData.allotmentLetter || null,
          pwdCert: formData.pwdCert || null,
        },
      });
    } catch (error) {
      console.error("Error handling admission form:", error);
      res.status(500).json({
        success: false,
        error: "Internal Server Error: " + error.message,
      });
    }
  }
);

// =================== ADMIN ROUTES ===================

// Admin login
app.post("/api/admin/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      console.log("❌ Missing credentials");
      return res.status(400).json({ error: "Username and password required" });
    }

    if (
      username === ADMIN_CREDENTIALS.username &&
      password === ADMIN_CREDENTIALS.password
    ) {
      const token = jwt.sign(
        { username: username, role: "admin" },
        JWT_SECRET,
        { expiresIn: "24h" }
      );

      console.log("✅ Login successful for:", username);

      res.json({
        success: true,
        message: "Login successful",
        token: token,
        user: { username: username, role: "admin" },
      });
    } else {
      console.log("❌ Invalid credentials provided:", { username, password });
      return res.status(401).json({ error: "Invalid credentials" });
    }
  } catch (error) {
    console.error("❌ Login error:", error);
    res.status(500).json({ error: "Internal server error: " + error.message });
  }
});

// Get all student applications with enhanced error handling
app.get("/api/admin/applications", authenticateToken, async (req, res) => {
  try {
    console.log("📊 Fetching applications from DynamoDB...");

    const result = await handleAWSOperation(
      () => dynamodb.send(new ScanCommand({ TableName: "Student" })),
      "DynamoDB Scan Applications"
    );

    console.log("📋 DynamoDB Scan Result:");
    console.log("- Count:", result.Count);
    console.log("- ScannedCount:", result.ScannedCount);
    console.log("- Items length:", result.Items?.length || 0);

    if (result.Items?.length > 0) {
      console.log("- First item keys:", Object.keys(result.Items[0]));
    } else {
      console.log("⚠️ No items found in Student table");
    }

    const applications = result.Items.sort((a, b) => {
      const dateA = new Date(a.submission_date || 0);
      const dateB = new Date(b.submission_date || 0);
      return dateB - dateA; // Most recent first
    });

    console.log("✅ Sending", applications.length, "applications to frontend");

    res.json({
      success: true,
      message: "Applications retrieved successfully",
      count: applications.length,
      applications: applications,
    });
  } catch (error) {
    console.error("Error fetching applications:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch applications: " + error.message,
    });
  }
});

// Get single application by email
app.get(
  "/api/admin/applications/:email",
  authenticateToken,
  async (req, res) => {
    try {
      const { email } = req.params;

      const result = await handleAWSOperation(
        () =>
          dynamodb.send(
            new ScanCommand({
              TableName: "Student",
              FilterExpression: "student_email = :email",
              ExpressionAttributeValues: {
                ":email": email.toLowerCase(),
              },
            })
          ),
        "DynamoDB Scan by Email"
      );

      if (result.Items.length === 0) {
        return res.status(404).json({ error: "Application not found" });
      }

      res.json({
        success: true,
        message: "Application retrieved successfully",
        application: result.Items[0],
      });
    } catch (error) {
      console.error("Error fetching application:", error);
      res
        .status(500)
        .json({ error: "Failed to fetch application: " + error.message });
    }
  }
);

// Dashboard statistics with enhanced error handling
app.get("/api/admin/statistics", authenticateToken, async (req, res) => {
  try {
    console.log("📊 Fetching statistics from DynamoDB...");

    const result = await handleAWSOperation(
      () => dynamodb.send(new ScanCommand({ TableName: "Student" })),
      "DynamoDB Scan Statistics"
    );

    const applications = result.Items;

    const stats = {
      totalApplications: applications.length,
      categoryBreakdown: {},
      genderBreakdown: {},
      admissionStatusBreakdown: {},
      physChallengedBreakdown: {},
      rankRanges: {
        "Below 1000": 0,
        "1000-5000": 0,
        "5000-10000": 0,
        "Above 10000": 0,
        "Not Specified": 0,
      },
    };

    applications.forEach((app) => {
      // Category breakdown
      const category = app.category || "Unknown";
      stats.categoryBreakdown[category] =
        (stats.categoryBreakdown[category] || 0) + 1;

      // Gender breakdown
      const gender = app.gender || "Unknown";
      stats.genderBreakdown[gender] = (stats.genderBreakdown[gender] || 0) + 1;

      // Admission status breakdown
      const admissionStatus = app.admissionStatus || "Unknown";
      stats.admissionStatusBreakdown[admissionStatus] =
        (stats.admissionStatusBreakdown[admissionStatus] || 0) + 1;

      // Physically challenged breakdown
      const physChallenged = app.physChallenged || "Unknown";
      stats.physChallengedBreakdown[physChallenged] =
        (stats.physChallengedBreakdown[physChallenged] || 0) + 1;

      // Rank ranges
      const rank = parseInt(app.crlRank);
      if (isNaN(rank)) {
        stats.rankRanges["Not Specified"]++;
      } else if (rank < 1000) {
        stats.rankRanges["Below 1000"]++;
      } else if (rank < 5000) {
        stats.rankRanges["1000-5000"]++;
      } else if (rank < 10000) {
        stats.rankRanges["5000-10000"]++;
      } else {
        stats.rankRanges["Above 10000"]++;
      }
    });

    res.json({
      success: true,
      message: "Statistics retrieved successfully",
      statistics: stats,
    });
  } catch (error) {
    console.error("Error fetching statistics:", error);
    res
      .status(500)
      .json({ error: "Failed to fetch statistics: " + error.message });
  }
});

// Excel download endpoint with enhanced error handling
app.get(
  "/api/admin/applications/download/excel",
  authenticateToken,
  async (req, res) => {
    try {
      console.log("Excel download requested");

      const result = await handleAWSOperation(
        () => dynamodb.send(new ScanCommand({ TableName: "Student" })),
        "DynamoDB Scan for Excel"
      );

      const applications = result.Items;

      if (applications.length === 0) {
        return res.status(404).json({ error: "No applications found" });
      }

      // Create workbook and worksheet with ExcelJS
      const workbook = new ExcelJS.Workbook();
      const worksheet = workbook.addWorksheet("Student Applications");

      // Define all columns with proper headers
      worksheet.columns = [
        { header: "S.No", key: "sno", width: 6 },
        { header: "Name", key: "name", width: 25 },
        { header: "Father Name", key: "fatherName", width: 25 },
        { header: "Mother Name", key: "motherName", width: 25 },
        { header: "Email", key: "email", width: 30 },
        { header: "Date of Birth", key: "dob", width: 15 },
        { header: "Gender", key: "gender", width: 10 },
        { header: "Nationality", key: "nationality", width: 15 },
        { header: "Religion", key: "religion", width: 15 },
        { header: "Category", key: "category", width: 12 },
        { header: "JEE Application Number", key: "applicationNum", width: 25 },
        { header: "CRL Rank", key: "crlRank", width: 12 },
        { header: "Mobile", key: "mobile", width: 15 },
        { header: "Alternate Mobile", key: "altMobile", width: 15 },
        { header: "Address", key: "address", width: 35 },
        { header: "Registration Fee Ref No", key: "refNo", width: 20 },
        { header: "Amount", key: "amount", width: 10 },
        { header: "Bank Name", key: "bank", width: 20 },
        { header: "Fee Payment Date", key: "date_feepayment", width: 15 },
        { header: "Physically Challenged", key: "physChallenged", width: 18 },
        {
          header: "Admission Status (JOSAA/CSAB)",
          key: "admissionStatus",
          width: 25,
        },
        { header: "Branch Name", key: "branchName", width: 20 },
        { header: "Department", key: "department", width: 20 },
        { header: "Class 12th Marksheet URL", key: "marksheet12", width: 40 },
        { header: "JEE Scorecard URL", key: "jeeScorecard", width: 40 },
        { header: "Category Certificate URL", key: "categoryCert", width: 40 },
        { header: "PWD Certificate URL", key: "pwdCert", width: 40 },
        { header: "Fee Receipt URL", key: "feeReceipt", width: 40 },
        { header: "Application Form URL", key: "appForm", width: 40 },
        { header: "Allotment Letter URL", key: "allotmentLetter", width: 40 },
        { header: "Submission Date", key: "submission_date", width: 20 },
        { header: "Submission ID", key: "submission_id", width: 25 },
      ];

      // Add header row styling
      const headerRow = worksheet.getRow(1);
      headerRow.font = { bold: true };
      headerRow.fill = {
        type: "pattern",
        pattern: "solid",
        fgColor: { argb: "FFE0E0E0" },
      };

      // Add data rows
      applications.forEach((app, index) => {
        worksheet.addRow({
          sno: index + 1,
          name: app.student_name || "",
          fatherName: app.fatherName || "",
          motherName: app.motherName || "",
          email: app.student_email || "",
          dob: app.dob || "",
          gender: app.gender || "",
          nationality: app.nationality || "",
          religion: app.religion || "",
          category: app.category || "",
          applicationNum: app.applicationNum || "",
          crlRank: app.crlRank || "",
          mobile: app.mobile || "",
          altMobile: app.altMobile || "",
          address: app.address || "",
          refNo: app.refNo || "",
          amount: app.amount || "",
          bank: app.bank || "",
          date_feepayment: app.date_feepayment || "",
          physChallenged: app.physChallenged || "",
          admissionStatus: app.admissionStatus || "",
          branchName: app.branchName || "",
          department: app.department || "",
          marksheet12: app.marksheet12 || "",
          jeeScorecard: app.jeeScorecard || "",
          categoryCert: app.categoryCert || "",
          pwdCert: app.pwdCert || "",
          feeReceipt: app.feeReceipt || "",
          appForm: app.appForm || "",
          allotmentLetter: app.allotmentLetter || "",
          submission_date: app.submission_date
            ? new Date(app.submission_date).toLocaleString("en-IN", {
                timeZone: "Asia/Kolkata",
              })
            : "",
          submission_id: app.submission_id || "",
        });
      });

      // Generate filename with current date
      const currentDate = new Date().toISOString().split("T")[0];
      const filename = `GGU_Student_Applications_${currentDate}.xlsx`;

      // Set response headers
      res.setHeader(
        "Content-Type",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
      );
      res.setHeader(
        "Content-Disposition",
        `attachment; filename="${filename}"`
      );

      console.log(
        `Generating Excel file: ${filename} with ${applications.length} applications`
      );

      // Send the Excel file
      await workbook.xlsx.write(res);
      res.end();

      console.log("Excel file sent successfully");
    } catch (error) {
      console.error("Error generating Excel file:", error);
      res
        .status(500)
        .json({ error: "Failed to generate Excel file: " + error.message });
    }
  }
);

// =================== ERROR HANDLING ===================

// =================== ERROR HANDLING ===================

// Handle 404 for API routes specifically (return JSON) - FIXED
app.use("/api/*path", (req, res) => {
  res.status(404).json({
    success: false,
    error: `API endpoint not found: ${req.method} ${req.originalUrl}`,
    message: "The requested API endpoint does not exist",
    availableEndpoints: [
      "POST /api/admission - Submit student application",
      "POST /api/admin/login - Admin login",
      "GET /api/admin/applications - Get all applications",
      "GET /api/admin/statistics - Get statistics",
      "GET /api/admin/applications/download/excel - Download Excel",
    ],
    timestamp: new Date().toISOString(),
  });
});

// Global error handler for API routes (return JSON) - FIXED
app.use("/api/*path", (err, req, res, next) => {
  console.error("API Error:", err);

  if (!res.headersSent) {
    res.status(err.status || 500).json({
      success: false,
      error: err.message || "Internal Server Error",
      timestamp: new Date().toISOString(),
    });
  }
});

// Handle 404 for non-API routes (return HTML)
app.use((req, res) => {
  res.status(404).send(`
    <!DOCTYPE html>
    <html>
    <head><title>404 - GGU</title></head>
    <body>
      <h1>404 - Page Not Found</h1>
      <p>GGU Admission System</p>
    </body>
    </html>
  `);
});

// =================== SERVER START ===================

app.listen(PORT, () => {
  console.log(`🚀 GGU Unified Server running at http://localhost:${PORT}`);
  console.log(`📝 Student submissions: POST /api/admission`);
  console.log(`👨‍💼 Admin login: POST /api/admin/login`);
  console.log(`📊 Admin dashboard: GET /api/admin/applications`);
  console.log(`📈 Admin statistics: GET /api/admin/statistics`);
  console.log(`📥 Excel download: GET /api/admin/applications/download/excel`);
});
