---
name: ficc-analysis-report
description: FICC 经营分析报告生成系统 - 基于 Anthropic financial-services-plugins 架构，支持 18 个业务团队的多维度经营分析
dependency:
  python:
    - anthropic>=0.42.0
    - pandas>=2.0.0
    - numpy>=1.24.0
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: cyhzzz/financial-services-plugins-ficc
# corpus-url: https://github.com/cyhzzz/financial-services-plugins-ficc/blob/03db83d5b13a528ab650e882e2247e60af2926a3/SKILL.md
# corpus-round: 2026-03-19
# corpus-format: markdown_fm
---

# FICC 经营分析报告生成系统

## 概述

本技能系统基于 **Anthropic financial-services-plugins** 架构设计，提供完整的 FICC（固定收益、外汇、大宗商品）经营分析能力，支持招商银行 18 个业务团队的多维度经营分析。

## 设计原则

遵循 Anthropic 的金融服务插件最佳实践：

1. **清晰的接口契约** - 标准化的输入/输出定义
2. **模块化设计** - 每个插件专注单一职责
3. **可观测性** - 完善的日志、指标、追踪
4. **安全优先** - 敏感数据访问控制
5. **容错设计** - 优雅降级和错误处理

## 架构设计

```
ficc-analysis-report/
│
├── manifest.yaml                    # 技能包清单
├── config.yaml                    # 全局配置
│
├── src/                           # 源代码
│   ├── __init__.py
│   ├── models/                    # 数据模型
│   │   ├── __init__.py
│   │   ├── portfolio.py         # 组合模型
│   │   ├── instrument.py        # 工具模型
│   │   ├── market_data.py       # 市场数据模型
│   │   └── report.py            # 报告模型
│   │
│   ├── core/                      # 核心能力
│   │   ├── __init__.py
│   │   ├── data_connector.py    # 数据连接
│   │   ├── curve_builder.py     # 曲线构建
│   │   ├── pricing_engine.py    # 定价引擎
│   │   └── risk_engine.py       # 风险引擎
│   │
│   ├── plugins/                   # 业务插件
│   │   ├── __init__.py
│   │   ├── fixed_income.py      # 固收业务
│   │   ├── fx_desk.py           # 外汇交易
│   │   ├── commodities.py       # 大宗商品
│   │   ├── client_solutions.py  # 客户解决方案
│   │   └── sales_trading.py     # 销售交易
│   │
│   └── workflows/                 # 工作流
│       ├── __init__.py
│       ├── report_generator.py  # 报告生成工作流
│       ├── data_collection.py   # 数据收集工作流
│       └── analysis_pipeline.py # 分析流水线
│
├── tests/                         # 测试
│   ├── unit/
│   ├── integration/
│   └── e2e/
│
└── docs/                          # 文档
    ├── api/
    ├── architecture/
    └── examples/
```

## 核心数据模型

### 组合模型 (Portfolio)

```python
from dataclasses import dataclass
from typing import List, Dict, Optional
from decimal import Decimal
from datetime import date

@dataclass
class Portfolio:
    """投资组合模型"""
    portfolio_id: str
    name: str
    business_line: str          # 业务线：固收/外汇/商品
    team: str                   # 团队
    as_of_date: date
    
    # 持仓
    positions: List['Position']
    
    # 汇总指标
    total_notional: Decimal
    market_value: Decimal
    ytd_pnl: Decimal
    
    # 风险指标
    var_1d: Optional[Decimal] = None
    var_10d: Optional[Decimal] = None
    
    # 元数据
    metadata: Dict = None

@dataclass
class Position:
    """持仓模型"""
    position_id: str
    instrument: 'Instrument'
    quantity: Decimal
    direction: str              # LONG / SHORT
    avg_cost: Decimal
    
    # 市场数据
    market_price: Decimal
    market_value: Decimal
    unrealized_pnl: Decimal
    
    # 风险
    delta: Optional[Decimal] = None
    gamma: Optional[Decimal] = None
    vega: Optional[Decimal] = None
```

### 工具模型 (Instrument)

```python
@dataclass
class Instrument:
    """金融工具基类"""
    instrument_id: str
    name: str
    instrument_type: str          # BOND / SWAP / OPTION / FUTURE / SPOT
    currency: str
    
    # 交易参数
    notional: Decimal
    maturity_date: Optional[date] = None
    
    # 定价参数
    pricing_model: Optional[str] = None
    model_params: Dict = None

@dataclass  
class Bond(Instrument):
    """债券"""
    face_value: Decimal
    coupon_rate: Decimal
    coupon_frequency: int           # 每年付息次数
    issue_date: date
    
    # 债券特有
    issuer: str
    credit_rating: Optional[str] = None
    
    # 计算指标
    ytm: Optional[Decimal] = None
    modified_duration: Optional[Decimal] = None
    convexity: Optional[Decimal] = None

@dataclass
class IRSwap(Instrument):
    """利率互换"""
    fixed_rate: Decimal
    fixed_leg_currency: str
    floating_index: str             # 如：SOFR, SHIBOR
    floating_spread: Decimal
    
    #  leg 详情
    fixed_leg_tenor: str
    floating_leg_tenor: str
    
    # 估值
    npv: Optional[Decimal] = None
    pv01: Optional[Decimal] = None
```

## 插件接口定义

### 固收业务插件 (Fixed Income)

```python
from abc import ABC, abstractmethod
from typing import List, Dict, Optional
from decimal import Decimal

class FixedIncomePlugin(ABC):
    """固收业务插件接口"""
    
    @abstractmethod
    def analyze_bond(self, bond: Bond, market_data: Dict) -> Dict:
        """
        分析债券
        
        Returns:
            {
                "ytm": Decimal,               # 到期收益率
                "duration": Decimal,          # 久期
                "convexity": Decimal,        # 凸性
                "credit_metrics": Dict       # 信用指标
            }
        """
        pass
    
    @abstractmethod
    def price_swap(self, swap: IRSwap, curves: Dict) -> Decimal:
        """
        定价利率互换
        
        Args:
            swap: 互换合约
            curves: {"discount": Curve, "forward": Curve}
            
        Returns:
            互换净现值
        """
        pass
    
    @abstractmethod
    def calculate_pnl_attribution(self, portfolio: Portfolio, 
                                   start_date: date, end_date: date) -> Dict:
        """
        计算损益归因
        
        五维度归因：Carry, Roll-down, Rate Change, Spread Change, Other
        """
        pass
```

## 使用示例

### 生成经营分析报告

```python
from ficc_analysis_report import FICCReportGenerator
from datetime import date

# 初始化报告生成器
report_gen = FICCReportGenerator(
    config={
        "business_line": "commodities",
        "team": "precious_metals",
        "data_mode": "guided"  # 或 "database"
    }
)

# 生成报告
report = report_gen.generate(
    period="2025Q1",
    report_type="business_analysis",
    output_format=["markdown", "h5"]
)

print(f"报告已生成: {report.markdown_path}")
print(f"H5页面: {report.h5_url}")
```

## 文档版本

- **Version**: 3.0
- **Architecture**: Anthropic Financial Services Plugins
- **Last Updated**: 2026-03-01