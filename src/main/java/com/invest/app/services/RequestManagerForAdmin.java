package com.invest.app.services;

import com.invest.app.requests.CreateInvestmentRequest;
import org.springframework.stereotype.Service;

@Service
public interface RequestManagerForAdmin {
    void createInvestment(CreateInvestmentRequest request);
}
