-- =====================================================
-- 药店管理系统 - openGauss 初始化脚本（含安全加固）
-- 整合 init.sql + 安全加固_表结构修改.sql
-- =====================================================

-- =============================================
-- 一、建表
-- =============================================

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL,
    real_name VARCHAR(50),
    phone VARCHAR(20),
    store_name VARCHAR(100),
    is_active BOOLEAN DEFAULT TRUE,
    last_login TIMESTAMP,
    login_attempts INT DEFAULT 0,
    locked_until TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE stores (
    id SERIAL PRIMARY KEY,
    pharmacy_code VARCHAR(20) UNIQUE,
    pharmacy_name VARCHAR(100),
    location TEXT,
    business_status BOOLEAN DEFAULT TRUE,
    business_hours VARCHAR(100),
    manager_user_id INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_stores_manager_user
        FOREIGN KEY (manager_user_id)
        REFERENCES users(id)
        ON DELETE SET NULL
);

CREATE TABLE categories (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT
);

CREATE TABLE suppliers (
    id SERIAL PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    contact_person VARCHAR(50),
    phone VARCHAR(20),
    address TEXT,
    rating INT DEFAULT 5,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE medicines (
    id SERIAL PRIMARY KEY,
    code VARCHAR(50) NOT NULL UNIQUE,
    name VARCHAR(200) NOT NULL,
    generic_name VARCHAR(200),
    category_id INT REFERENCES categories(id),
    spec VARCHAR(100),
    unit VARCHAR(20) DEFAULT '盒',
    manufacturer VARCHAR(200),
    approval_no VARCHAR(100),
    is_rx BOOLEAN DEFAULT FALSE,
    purchase_price DECIMAL(10,2) DEFAULT 0.00,
    price DECIMAL(10,2) NOT NULL,
    stock INT DEFAULT 0,
    warning_stock INT DEFAULT 20,
    store_name VARCHAR(100) NOT NULL,
    description TEXT,
    usage_method TEXT,
    adverse_reaction TEXT,
    storage_condition TEXT,
    image_path VARCHAR(500),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE medicine_batches (
    id SERIAL PRIMARY KEY,
    medicine_id INT REFERENCES medicines(id),
    batch_no VARCHAR(100) NOT NULL,
    supplier_id INT REFERENCES suppliers(id),
    production_date DATE,
    expiry_date DATE,
    quantity INT DEFAULT 0,
    remain_quantity INT DEFAULT 0,
    purchase_price DECIMAL(10,2),
    store_name VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE price_change_requests (
    id SERIAL PRIMARY KEY,
    medicine_id INT REFERENCES medicines(id),
    old_price DECIMAL(10,2),
    new_price DECIMAL(10,2),
    reason TEXT,
    status VARCHAR(20) DEFAULT '待审批',
    request_by VARCHAR(50),
    approve_by VARCHAR(50),
    approve_remark TEXT,
    requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    approved_at TIMESTAMP
);

CREATE TABLE stock_in_orders (
    id SERIAL PRIMARY KEY,
    order_no VARCHAR(50) NOT NULL UNIQUE,
    supplier_id INT REFERENCES suppliers(id),
    store_name VARCHAR(100) NOT NULL,
    status VARCHAR(20) DEFAULT '已入库',
    total_amount DECIMAL(12,2),
    created_by VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE stock_in_items (
    id SERIAL PRIMARY KEY,
    order_id INT REFERENCES stock_in_orders(id),
    medicine_id INT REFERENCES medicines(id),
    batch_no VARCHAR(100),
    quantity INT NOT NULL,
    purchase_price DECIMAL(10,2),
    amount DECIMAL(12,2),
    production_date DATE,
    expiry_date DATE
);

CREATE TABLE stock_transfer_orders (
    id SERIAL PRIMARY KEY,
    order_no VARCHAR(50) NOT NULL UNIQUE,
    medicine_id INT REFERENCES medicines(id),
    quantity INT NOT NULL,
    from_store VARCHAR(100),
    to_store VARCHAR(100),
    status VARCHAR(20) DEFAULT '待处理',
    created_by VARCHAR(50),
    approved_by VARCHAR(50),
    remark TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    approved_at TIMESTAMP
);

CREATE TABLE stock_transfer_items (
    id SERIAL PRIMARY KEY,
    transfer_order_id INT REFERENCES stock_transfer_orders(id),
    medicine_id INT REFERENCES medicines(id),
    quantity INT
);

CREATE TABLE inventory_logs (
    id SERIAL PRIMARY KEY,
    medicine_id INT REFERENCES medicines(id),
    change_type VARCHAR(50),
    change_qty INT,
    before_stock INT,
    after_stock INT,
    ref_type VARCHAR(50),
    ref_id INT,
    store_name VARCHAR(100),
    operator_name VARCHAR(50),
    remark TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE drug_suggestions (
    id SERIAL PRIMARY KEY,
    medicine_name VARCHAR(200),
    medicine_type VARCHAR(100),
    suggest_qty INT,
    estimate_price DECIMAL(10,2),
    reason TEXT,
    supplier_suggestion TEXT,
    submitter VARCHAR(50),
    store_name VARCHAR(100),
    status VARCHAR(20) DEFAULT '待审批',
    admin_reply TEXT,
    replied_by VARCHAR(50),
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    replied_at TIMESTAMP
);

CREATE TABLE sales_orders (
    id SERIAL PRIMARY KEY,
    order_no VARCHAR(50) NOT NULL UNIQUE,
    total_amount DECIMAL(12,2),
    actual_amount DECIMAL(12,2),
    payment_method VARCHAR(20),
    payment_status VARCHAR(20) DEFAULT '已支付',
    cashier VARCHAR(50),
    store_name VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE sales_items (
    id SERIAL PRIMARY KEY,
    order_id INT REFERENCES sales_orders(id),
    medicine_id INT REFERENCES medicines(id),
    quantity INT NOT NULL,
    unit_price DECIMAL(10,2),
    amount DECIMAL(12,2)
);

CREATE TABLE return_orders (
    id SERIAL PRIMARY KEY,
    order_no VARCHAR(50) NOT NULL UNIQUE,
    sale_order_no VARCHAR(50),
    medicine_id INT REFERENCES medicines(id),
    quantity INT,
    refund_amount DECIMAL(12,2),
    total_refund_amount DECIMAL(12,2),
    reason TEXT,
    operator_name VARCHAR(50),
    store_name VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE return_items (
    id SERIAL PRIMARY KEY,
    return_order_no VARCHAR(50) REFERENCES return_orders(order_no),
    medicine_id INT REFERENCES medicines(id),
    quantity INT,
    unit_price DECIMAL(10,2),
    refund_amount DECIMAL(12,2)
);

CREATE TABLE payments (
    id SERIAL PRIMARY KEY,
    order_no VARCHAR(50),
    pay_type VARCHAR(20),
    pay_amount DECIMAL(12,2),
    pay_status VARCHAR(20),
    operator_name VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50),
    action VARCHAR(100),
    detail TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    table_name VARCHAR(100),
    record_id INTEGER,
    old_value TEXT,
    new_value TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE user_sessions (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    session_token VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =============================================
-- 二、插入基础数据
-- =============================================

INSERT INTO users (username, password, role, real_name, phone, store_name) VALUES
('admin', 'admin123', '系统管理员', '系统管理员', '13800000000', '总部'),
('manager1', '123456', '药房管理员', '张店长', '13811111111', '总店'),
('manager2', '123456', '药房管理员', '李店长', '13822222222', '分店一'),
('manager3', '123456', '药房管理员', '王店长', '13855555555', '分店二'),
('seller1', '123456', '销售员', '王销售', '13833333333', '总店'),
('seller2', '123456', '销售员', '刘销售', '13844444444', '分店一'),
('seller3', '123456', '销售员', '赵销售', '13866666666', '分店二');

INSERT INTO stores (pharmacy_code, pharmacy_name, location, business_status, business_hours, manager_user_id)
SELECT 'P001', '总店', '市中心中山路1号', TRUE, '08:00-22:00', id FROM users WHERE username = 'manager1';

INSERT INTO stores (pharmacy_code, pharmacy_name, location, business_status, business_hours, manager_user_id)
SELECT 'P002', '分店一', '城东新区人民路2号', TRUE, '08:00-21:00', id FROM users WHERE username = 'manager2';

INSERT INTO stores (pharmacy_code, pharmacy_name, location, business_status, business_hours, manager_user_id)
SELECT 'P003', '分店二', '城西解放路3号', TRUE, '09:00-20:00', id FROM users WHERE username = 'manager3';

INSERT INTO categories (name, description) VALUES
('抗生素', '抗菌消炎类药物'),
('解热镇痛', '退烧止痛类药物'),
('心脑血管', '高血压、心脏病等'),
('维生素', '维生素与矿物质补充剂'),
('消化系统', '胃肠用药'),
('呼吸系统', '止咳化痰平喘'),
('中成药', '中药制剂'),
('外用药', '外用膏贴、洗剂');

INSERT INTO suppliers (name, contact_person, phone, address, rating) VALUES
('华北制药', '赵经理', '0311-88888888', '河北省石家庄市', 5),
('中美史克', '钱经理', '022-66666666', '天津市', 5),
('广州白云山', '孙经理', '020-88888888', '广州市白云区', 5),
('东北制药', '李经理', '024-88888888', '沈阳市', 4),
('哈药集团', '周经理', '0451-88888888', '哈尔滨市', 5),
('天津中新药业', '吴经理', '022-77777777', '天津市', 4),
('上海先灵葆雅', '郑经理', '021-66666666', '上海市', 5),
('拜耳医药', '王经理', '010-88888888', '北京市', 5),
('扬子江药业', '冯经理', '0523-88888888', '江苏泰州', 5),
('三九医药', '陈经理', '0755-88888888', '深圳市', 4),
('云南白药', '褚经理', '0871-88888888', '昆明市', 5),
('同仁堂', '卫经理', '010-88888888', '北京市', 5);

-- =============================================
-- 三、批量生成 100 条药品
-- =============================================
INSERT INTO medicines (
    code, name, generic_name, category_id, spec, unit, manufacturer,
    approval_no, is_rx, price, stock, warning_stock, store_name,
    description, usage_method, adverse_reaction, storage_condition
)
SELECT
    'YP' || LPAD(i::TEXT, 3, '0'),
    CASE (i % 20)
        WHEN 0 THEN '阿莫西林胶囊' WHEN 1 THEN '布洛芬片' WHEN 2 THEN '板蓝根颗粒'
        WHEN 3 THEN '维生素C片' WHEN 4 THEN '头孢克肟片' WHEN 5 THEN '复方丹参片'
        WHEN 6 THEN '氨氯地平片' WHEN 7 THEN '双黄连口服液' WHEN 8 THEN '阿司匹林肠溶片'
        WHEN 9 THEN '罗红霉素分散片' WHEN 10 THEN '感冒灵颗粒' WHEN 11 THEN '藿香正气水'
        WHEN 12 THEN '氯雷他定片' WHEN 13 THEN '奥美拉唑肠溶胶囊' WHEN 14 THEN '蒙脱石散'
        WHEN 15 THEN '云南白药气雾剂' WHEN 16 THEN '六味地黄丸' WHEN 17 THEN '牛黄解毒片'
        WHEN 18 THEN '健胃消食片' WHEN 19 THEN '速效救心丸' ELSE '未知药品'
    END || ' ' || i,
    CASE (i % 20)
        WHEN 0 THEN 'Amoxicillin' WHEN 1 THEN 'Ibuprofen' WHEN 2 THEN 'Banlangen'
        WHEN 3 THEN 'Vitamin C' WHEN 4 THEN 'Cefixime' WHEN 5 THEN 'Compound Danshen'
        WHEN 6 THEN 'Amlodipine' WHEN 7 THEN 'Shuanghuanglian' WHEN 8 THEN 'Aspirin'
        WHEN 9 THEN 'Roxithromycin' WHEN 10 THEN 'Ganmaoling' WHEN 11 THEN 'Huoxiang Zhengqi'
        WHEN 12 THEN 'Loratadine' WHEN 13 THEN 'Omeprazole' WHEN 14 THEN 'Montmorillonite'
        WHEN 15 THEN 'Yunnan Baiyao' WHEN 16 THEN 'Liuwei Dihuang' WHEN 17 THEN 'Niuhuang Jiedu'
        WHEN 18 THEN 'Jianwei Xiaoshi' WHEN 19 THEN 'Suxiao Jiuxin' ELSE 'Unknown'
    END,
    1 + ((i - 1) % 8),
    '0.' || (100 + i) || 'g/盒',
    '盒',
    (SELECT name FROM suppliers WHERE id = 1 + ((i - 1) % 12)),
    '国药准字H' || LPAD(i::TEXT, 8, '0'),
    i % 2 = 0,
    ROUND((5 + random() * 45)::numeric, 2),
    50 + (i * 7) % 300,
    20 + (i % 30),
    CASE (i % 3) WHEN 0 THEN '总店' WHEN 1 THEN '分店一' WHEN 2 THEN '分店二' END,
    '本品为常用药品，用于治疗相关症状。',
    '口服，一次1-2粒，一日2-3次。',
    '偶见胃肠道不适，过敏反应。',
    '密封，置阴凉干燥处。'
FROM generate_series(1, 100) AS i;

UPDATE medicines SET purchase_price = ROUND(price * (0.6 + random() * 0.25), 2);

UPDATE medicine_batches mb
SET purchase_price = (SELECT m.purchase_price FROM medicines m WHERE m.id = mb.medicine_id)
WHERE mb.purchase_price IS NULL;

UPDATE medicines SET image_path = '/images/drug' || id || '.jpg' WHERE id % 3 = 0;

-- =============================================
-- 四、插入销售示例
-- =============================================
INSERT INTO sales_orders (order_no, total_amount, actual_amount, payment_method, cashier, store_name, created_at)
VALUES
('SO20240418001', 125.50, 125.50, '微信', 'seller1', '总店', '2026-04-18 10:30:00'),
('SO20240418002', 89.00, 89.00, '支付宝', 'seller1', '总店', '2026-04-18 14:20:00'),
('SO20240417001', 230.00, 230.00, '现金', 'seller2', '分店一', '2026-04-17 09:15:00');

INSERT INTO sales_items (order_id, medicine_id, quantity, unit_price, amount)
SELECT 1, 1, 2, 12.50, 25.00 UNION ALL
SELECT 1, 2, 5, 8.80, 44.00 UNION ALL
SELECT 2, 3, 3, 15.00, 45.00;

-- 触发低库存预警
UPDATE medicines SET stock = warning_stock - 5 WHERE id IN (2, 5, 10, 18, 25, 30, 45, 60, 75, 90);
