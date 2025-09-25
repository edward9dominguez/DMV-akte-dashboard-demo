/* ======================================================================
   AKTE FAST Analysis — Demo Query (Portfolio-Safe)
   Notes:
   - Table and schema names are GENERIC for demonstration.
   - All personally identifying fields are removed or hashed.
   - Designed for Tableau parameters but will run in Snowflake-like SQL.
   - Toggle the DL LEFT JOIN at the bottom if you don’t want to show it.
   ====================================================================== */

/* -------- Parameters (Tableau-style placeholders) -------- */
WITH params AS (
  SELECT
    CAST(<Parameters.StartDate> AS TIMESTAMP_NTZ)                 AS ts_start,
    CAST(DATEADD(day, 1, <Parameters.EndDate>) AS TIMESTAMP_NTZ)  AS ts_end_excl,
    /* window (secs) to link fingerprint audit to a session */
    <Parameters.XSecondaryVerificationSecs>                       AS x_secs
),

/* -------- Exclude specific test types (business rule) -------- */
exclude_test_ids AS (
  SELECT T.TEST_ID
  FROM PUBLIC_AKTE.REF_TESTS T
  WHERE T.TEST_NAME IN (
    'Ambulance Test',
    'Dealer Test',
    'Driving School Instructor Test',
    'Driving School Operator Test',
    'Firefighter Endorsement Test',
    'Traffic Violator School Instructor Test',
    'Traffic Violator School Operator Test'
  )
),

/* -------- Sessions in the date window -------- */
sess_f AS (
  SELECT
    S.SESSION_ID,
    S.OFFICE_ID,
    S.VAULT_ID,
    /* Hash workstation IP to remove direct identifiers */
    SHA2(TRIM(S.WORKSTATION_IP_ADDR), 256) AS workstation_ip_hash,
    S.SESSION_START_TME,
    S.LSTMODUSR_NME
  FROM PUBLIC_AKTE.FACT_SESSIONS S
  JOIN params p ON 1=1
  WHERE S.SESSION_START_TME >= p.ts_start
    AND S.SESSION_START_TME <  p.ts_end_excl
),

/* -------- Audit events (fingerprint failures) -------- */
audit_f AS (
  SELECT
    /* audit RETRIEVAL_KEY is an IP; hash to match hashed session IP */
    SHA2(TRIM(J.RETRIEVAL_KEY), 256) AS retrieval_key_hash,
    J.LSTMODUSR_TME                  AS audit_time
  FROM PUBLIC_AKTE.AUDIT_HISTORY J
  JOIN params p ON 1=1
  WHERE J.TABLE_NME = 'FINGERPRINT'
    AND J.FIELD_NME = 'ERROR'
    AND J.NEW_VALUE LIKE 'Reached max of 3%'
    AND J.LSTMODUSR_TME >= p.ts_start
    AND J.LSTMODUSR_TME <  p.ts_end_excl
    AND SHA2(TRIM(J.RETRIEVAL_KEY), 256) IN (SELECT workstation_ip_hash FROM sess_f)
),

/* -------- Exams (scoped & filtered) -------- */
exam_f AS (
  SELECT
    E.SESSION_ID, E.OFFICE_ID, E.EXAM_ID, E.TEST_ID, E.LANG_ID,
    E.CDL_FLG, E.PASS_FAIL_IND, E.EXAM_START_TME, E.EXAM_END_TME,
    E.EXAM_QUES_NBR, E.MAX_INCORR_NBR, E.INCORR_ANS_CNT,
    E.CORR_QUES_CNT, E.QUES_ANSW_CNT, E.SCORE, E.CMPLTN_RSN_CD
  FROM PUBLIC_AKTE.FACT_EXAMS E
  JOIN params p ON 1=1
  WHERE E.PASS_FAIL_IND IN ('P','F')
    AND E.EXAM_START_TME >= p.ts_start
    AND E.EXAM_START_TME <  p.ts_end_excl
    AND E.EXAM_START_TME <  E.EXAM_END_TME           -- positive durations only
    AND E.CMPLTN_RSN_CD NOT IN ('B','F')             -- exclude abandoned/failed-to-complete reasons
    AND NOT EXISTS (SELECT 1 FROM exclude_test_ids x WHERE x.TEST_ID = E.TEST_ID)
),

/* -------- Vault (only what we need; hash DL) -------- */
vault_lkp AS (
  SELECT
    V.VAULT_ID,
    /* Hash the DL number; never expose raw */
    SHA2(TRIM(V.DL_NBR), 256) AS DRIVER_ID_HASH
  FROM PUBLIC_AKTE.DIM_VAULT V
  WHERE V.VAULT_ID IN (SELECT DISTINCT VAULT_ID FROM sess_f)
),

/* -------- Link audit to session within X seconds -------- */
audit_session AS (
  SELECT
    S.SESSION_ID, S.OFFICE_ID, S.VAULT_ID,
    S.workstation_ip_hash, S.SESSION_START_TME, S.LSTMODUSR_NME,
    A.audit_time,
    ABS(DATEDIFF('second', A.audit_time, S.SESSION_START_TME)) AS secs_session_from_audit
  FROM sess_f S
  JOIN audit_f A
    ON A.retrieval_key_hash = S.workstation_ip_hash
   AND S.SESSION_START_TME BETWEEN A.audit_time
                               AND DATEADD(second, (SELECT x_secs FROM params), A.audit_time)
  QUALIFY ROW_NUMBER() OVER (
            PARTITION BY S.SESSION_ID
            ORDER BY secs_session_from_audit ASC
          ) = 1
),

/* -------- Core facts (no PII) -------- */
core AS (
  SELECT
    S.workstation_ip_hash                    AS WORKSTATION_IP_HASH,
    S.OFFICE_ID,
    V.DRIVER_ID_HASH,
    S.SESSION_START_TME,
    S.LSTMODUSR_NME,
    E.PASS_FAIL_IND, E.EXAM_ID, E.TEST_ID, E.LANG_ID, E.CDL_FLG,
    E.EXAM_START_TME, E.EXAM_END_TME,
    E.EXAM_QUES_NBR, E.MAX_INCORR_NBR, E.INCORR_ANS_CNT,
    E.CORR_QUES_CNT, E.QUES_ANSW_CNT, E.SCORE, E.CMPLTN_RSN_CD,
    A.audit_time,
    DATEDIFF('second', A.audit_time, E.EXAM_START_TME) AS secs_audit_to_exam,
    IFF(A.audit_time IS NOT NULL, 1, 0) AS SECONDARY_VERIF_FLAG
  FROM exam_f E
  JOIN sess_f S
    ON S.SESSION_ID = E.SESSION_ID
   AND S.OFFICE_ID  = E.OFFICE_ID
  JOIN vault_lkp V
    ON V.VAULT_ID = S.VAULT_ID
  LEFT JOIN audit_session A
    ON A.SESSION_ID = S.SESSION_ID
   AND A.OFFICE_ID  = S.OFFICE_ID
)

/* -------- Final (dimensions + convenience) -------- */
SELECT
  /* session */
  C.WORKSTATION_IP_HASH,
  C.OFFICE_ID,
  TRIM(UPPER(O.OFFICE_NME)) || ' (' || TRIM(TO_VARCHAR(O.OFFICE_ID)) || ')' AS OFFICE_LABEL,

  /* exam */
  C.PASS_FAIL_IND            AS PASSFAIL,
  C.EXAM_ID                  AS EXAMID,
  C.CDL_FLG                  AS CDLFLAG,
  C.EXAM_START_TME           AS EXAMSTART,
  C.EXAM_END_TME             AS EXAMEND,

  /* metrics */
  C.EXAM_QUES_NBR, C.MAX_INCORR_NBR, C.INCORR_ANS_CNT,
  C.CORR_QUES_CNT, C.QUES_ANSW_CNT, C.SCORE, C.CMPLTN_RSN_CD,

  /* convenience */
  CAST(C.EXAM_END_TME AS DATE) AS COMPLETED_DATE,
  DATEDIFF('second', C.EXAM_START_TME, C.EXAM_END_TME) AS EXAM_DUR_SECS,
  DATEDIFF('minute', C.EXAM_START_TME, C.EXAM_END_TME) AS EXAM_DUR_MINS,
  DATE_TRUNC('week', C.EXAM_START_TME)                 AS EXAM_WEEK_START,
  TO_VARCHAR(C.EXAM_START_TME, 'DY')                   AS EXAM_DOW_ABBR,

  /* dims */
  O.OFFICE_NME,
  T.TEST_NAME,
  L.LANG_NME AS LANGUAGE,

  /* Tableau-friendly counters */
  IFF(C.PASS_FAIL_IND='P',1,0) AS PASSCNTR,
  IFF(C.PASS_FAIL_IND='F',1,0) AS FAILCNTR,
  IFF(C.CDL_FLG='Y',1,0)       AS CDLCNTR,
  1 AS CNTR,

  /* audit linkage */
  C.SECONDARY_VERIF_FLAG,
  C.audit_time                 AS AUDIT_TIME,
  C.secs_audit_to_exam         AS SECS_AUDIT_TO_EXAM,

  /* --- Optional DL columns (non-PII) --- */
  D.DL_CLASS_CD,
  D.MAIL_CITY,
  D.MAIL_ADDR_EFF_DT

FROM core C
JOIN PUBLIC_AKTE.DIM_OFFICE O ON O.OFFICE_ID = C.OFFICE_ID
JOIN PUBLIC_AKTE.REF_TESTS  T ON T.TEST_ID   = C.TEST_ID
JOIN PUBLIC_AKTE.REF_LANG   L ON L.LANG_ID   = C.LANG_ID

/* Keep this join if you want extra NON-PII DL attributes; otherwise comment it out */
LEFT JOIN PUBLIC_DL.V_DL_MASTER_NONCONF D
       ON C.DRIVER_ID_HASH = SHA2(TRIM(D.DLID_NBR), 256)
;
