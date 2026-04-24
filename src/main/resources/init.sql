-- 创建 sys_user 表
CREATE TABLE IF NOT EXISTS sys_user (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(100) NOT NULL
);

-- 创建 user_info 表
CREATE TABLE IF NOT EXISTS user_info (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    real_name VARCHAR(50),
    phone VARCHAR(20),
    address VARCHAR(200),
    user_id BIGINT NOT NULL UNIQUE
);

-- 插入测试数据
INSERT INTO sys_user (username, password) VALUES ('admin', '123');
INSERT INTO sys_user (username, password) VALUES ('user1', '123');
INSERT INTO sys_user (username, password) VALUES ('user2', '123');
INSERT INTO sys_user (username, password) VALUES ('user3', '123');
INSERT INTO sys_user (username, password) VALUES ('user4', '123');
INSERT INTO sys_user (username, password) VALUES ('user5', '123');
INSERT INTO sys_user (username, password) VALUES ('user6', '123');

-- 插入 user_info 测试数据
INSERT INTO user_info (real_name, phone, address, user_id) VALUES ('张三', '13812345678', '北京市朝阳区', 1);
INSERT INTO user_info (real_name, phone, address, user_id) VALUES ('李四', '13987654321', '上海市浦东新区', 2);
INSERT INTO user_info (real_name, phone, address, user_id) VALUES ('王五', '13712345678', '广州市天河区', 3);
INSERT INTO user_info (real_name, phone, address, user_id) VALUES ('赵六', '13687654321', '深圳市南山区', 4);
INSERT INTO user_info (real_name, phone, address, user_id) VALUES ('钱七', '13512345678', '杭州市西湖区', 5);
INSERT INTO user_info (real_name, phone, address, user_id) VALUES ('孙八', '13487654321', '成都市锦江区', 6);
INSERT INTO user_info (real_name, phone, address, user_id) VALUES ('周九', '13312345678', '武汉市江汉区', 7);