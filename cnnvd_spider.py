import requests
from bs4 import BeautifulSoup
import json
import csv
import sys
import os

header = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36"}


def parse_main_pages(json_file_path):
    """
    以页数为参数，遍历每一页，对每一页面的爬取到的html信息
    处理为beautifulsoup对象，并调用parse_vuln_pages()函数进一步处理
    """
    for i in range(1, 5):  # 访问5页
        try:
            url = "http://www.cnnvd.org.cn/web/vulnerability/querylist.tag?pageno=" + str(
                i) + "&repairLd="  # 遍历访问5页中的每一页
            response = requests.get(url, headers=header, timeout=30)
            response.encoding = response.apparent_encoding
            bs = BeautifulSoup(markup=response.text, features="html.parser")
            parse_vuln_pages(bs, json_file_path)
            print("[SUCCESS] page", str(i), "parse ok")
        except Exception as e:  # 访问出错
            print("[ERROR] wrong page", str(i), "error:", e)
            continue
    print("[END]parse all over")


def parse_vuln_pages(response, json_file_path):
    """
    从每一页中，提取出10个漏洞的具体地址，访问漏洞详情页面并处理为beautifulsoup对象
    传递给parse_detail()函数执行
    :param response:从parse_main_pages()中传递过来的每一页的beautifulsoup对象
    """
    # href属性通过标签进行选取
    items = response.find_all('a', class_="a_title2")  # 找class为a_title2的a标签,item是tag类型
    for item in items:
        url = "http://www.cnnvd.org.cn" + item['href']  # 从href属性中提取每个漏洞详情页的相对地址，并和主url拼接得到漏洞详情页的具体url
        response = requests.get(url, headers=header, timeout=30)
        response.encoding = response.apparent_encoding
        bs = BeautifulSoup(markup=response.text, features="html.parser")
        parse_detail(bs, json_file_path)


def parse_detail(response, json_file_path):
    """
    从每个漏洞详情页中提取信息，保存为字典值，并更新到全局的total中
    :param response: 从parse_vuln_pages()中传递过来的每个漏洞详情页的beautifulsoup对象
    :return:
    """
    li_tags = response.find_all('li', limit=16)  # 提取所有的li标签
    vuln_name = response.find_all('h2', limit=2)[1].text.strip()  # 页面中第二个h2标签的text内容即为漏洞名称
    cnnvd_num = li_tags[9].text.replace("CNNVD编号：", "")  # 第10个li标签的text内容是CNNVD编号
    publish_time = li_tags[13].text.replace("发布时间：", "").strip()  # 第14个li标签的text内容是漏洞发布时间
    update_time = li_tags[15].text.replace("更新时间：", "").strip()  # 以此类推
    harm_level = li_tags[10].text.replace("危害等级：", "").strip()
    vuln_type = li_tags[12].text.replace("漏洞类型：", "").strip()
    threaten_type = li_tags[14].text.replace("威胁类型：", "").strip()
    cve_num = li_tags[11].text.replace("CVE编号：", "").strip()
    vuln_detail_tag = response.find('div', class_="d_ldjj")  # class属性为d_ldjj的div标签的text值即为漏洞简介
    vuln_detail = vuln_detail_tag.text.replace("\n\n漏洞简介\n\n\n\n\t\t\t\t", "").replace("\n", "").strip()
    vuln = {"漏洞名称": vuln_name, "CNNVD编号": cnnvd_num, "发布时间": publish_time, "更新时间": update_time, "危害等级": harm_level,
            "漏洞类型": vuln_type, "威胁类型": threaten_type, "CVE编号": cve_num, "漏洞简介": vuln_detail}
    with open(json_file_path, 'a', encoding='utf-8') as json_file:
        json_file.write(json.dumps(vuln))
        json_file.write("\n")  # 写入换行符
        json_file.close()
    print(vuln)


def json2csv(json_path, csv_path):
    csv_headers = ['漏洞名称', 'CNNVD编号', '发布时间', '更新时间', '危害等级', '漏洞类型', '威胁类型', 'CVE编号', '漏洞简介']
    csv_file = open(csv_path, 'w', encoding="utf-8-sig", newline="")
    csv_write = csv.writer(csv_file)
    csv_write.writerow(csv_headers)
    print("start write csv file...")
    with open(json_path, encoding="utf-8") as json_file:
        json_datas = json_file.readlines()
    for json_data in json_datas:
        # json_data = json_data.replace("\n", "")
        dict_data = json.loads(json_data)
        vuln_name = dict_data['漏洞名称']
        cnnvd_num = dict_data['CNNVD编号']
        publish_time = dict_data['发布时间']
        update_time = dict_data['更新时间']
        harm_level = dict_data['危害等级']
        vuln_type = dict_data['漏洞类型']
        threaten_type = dict_data['威胁类型']
        cve_num = dict_data['CVE编号']
        vuln_detail = dict_data['漏洞简介']
        row_data = [vuln_name, cnnvd_num, publish_time, update_time, harm_level, vuln_type, threaten_type, cve_num,
                    vuln_detail]
        csv_write.writerow(row_data)
    print("write csv file", csv_path, "ok")


if __name__ == "__main__":
    print("usage:python3 cnnvd_spider.py <csv_file_name with path>\n")
    argv_len = len(sys.argv)
    if argv_len == 2:
        csv_file_path = sys.argv[1]
        json_file_path = csv_file_path.split(".")[0] + ".json"
    else:
        print("as you didn't point out the file name,csv file will be saved")
        print("at the same path with the cnnvd_spider.py and  it's name is cnnvd.csv")
        csv_file_path = "cnnvd.csv"
        json_file_path = "cnnvd.json"
    if os.path.exists(csv_file_path):
        print(csv_file_path, "has been generated,try to change your csv file name or check this csv file")
        exit(0)
    else:
        pass
    parse_main_pages(json_file_path)
    json2csv(json_file_path, csv_file_path)
